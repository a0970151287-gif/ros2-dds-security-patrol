"""
LiDAR-aware feature extractor for TQC actor & critic networks.

Architecture:
    Input  : flat Box obs of shape (K * (n_lidar + n_state),)
             — K stacked frames; each frame = [lidar (180), state (6)]

    LiDAR branch (1D Conv across beams, K frames as channels):
        Reshape          → (B, K, 180)
        Conv1D(32, k=5)  + ReLU
        Conv1D(64, k=3)  + ReLU
        AdaptiveAvgPool1d(8) + Flatten   → (B, 512)
        LayerNorm + Linear(192) + ReLU   → (B, 192)

    State branch (small MLP on stacked state):
        Flatten K*6 → Linear(64) → LayerNorm → ReLU   → (B, 64)

    Fusion : concat (B, 256) → Linear(features_dim) → LayerNorm → ReLU
"""
from __future__ import annotations

import torch as th
from torch import nn
from gymnasium import spaces
from stable_baselines3.common.torch_layers import BaseFeaturesExtractor


class LiDARConvExtractor(BaseFeaturesExtractor):
    def __init__(
        self,
        observation_space: spaces.Box,
        frame_stack: int = 4,
        lidar_beams: int = 180,
        state_dim: int = 6,
        features_dim: int = 256,
    ) -> None:
        super().__init__(observation_space, features_dim=features_dim)
        self.k = frame_stack
        self.n_lidar = lidar_beams
        self.n_state = state_dim
        per_frame = lidar_beams + state_dim
        expected = frame_stack * per_frame
        assert observation_space.shape[0] == expected, (
            f"obs dim {observation_space.shape[0]} != "
            f"K({frame_stack}) * per_frame({per_frame}) = {expected}"
        )

        # LiDAR encoder: per-frame Conv1D, frames treated as channels
        self.lidar_conv = nn.Sequential(
            nn.Conv1d(frame_stack, 32, kernel_size=5, padding=2),
            nn.ReLU(inplace=True),
            nn.Conv1d(32, 64, kernel_size=3, padding=1),
            nn.ReLU(inplace=True),
            nn.AdaptiveAvgPool1d(8),
            nn.Flatten(),
            nn.LayerNorm(64 * 8),
            nn.Linear(64 * 8, 192),
            nn.ReLU(inplace=True),
        )

        self.state_mlp = nn.Sequential(
            nn.Linear(frame_stack * state_dim, 64),
            nn.LayerNorm(64),
            nn.ReLU(inplace=True),
        )

        self.fuse = nn.Sequential(
            nn.Linear(192 + 64, features_dim),
            nn.LayerNorm(features_dim),
            nn.ReLU(inplace=True),
        )

    def forward(self, obs: th.Tensor) -> th.Tensor:
        B = obs.shape[0]
        per_frame = self.n_lidar + self.n_state
        x = obs.view(B, self.k, per_frame)
        lidar = x[..., : self.n_lidar]            # (B, K, n_lidar)
        state = x[..., self.n_lidar :]            # (B, K, n_state)
        lidar_feat = self.lidar_conv(lidar)       # (B, 192)
        state_feat = self.state_mlp(state.reshape(B, -1))  # (B, 64)
        return self.fuse(th.cat([lidar_feat, state_feat], dim=-1))
