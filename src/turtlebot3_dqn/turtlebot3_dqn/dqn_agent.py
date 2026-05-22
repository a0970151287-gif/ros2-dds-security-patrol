"""Double Dueling DQN Agent（純避障版）"""
import math
import torch
import torch.nn as nn
import torch.nn.functional as F
import torch.optim as optim
from torch.amp import GradScaler, autocast
import numpy as np
from pathlib import Path
from .replay_buffer import ReplayBuffer

STATE_SIZE          = 24
ACTION_SIZE         = 5

BATCH_SIZE          = 64
GAMMA               = 0.99
LR                  = 5e-4
EPSILON_START       = 1.0
EPSILON_END         = 0.05
EPSILON_DECAY_STEPS = 12000   # 約 40 集（每集 300 步）後到 0.4
TAU                 = 0.005


class DuelingDQN(nn.Module):
    def __init__(self, state_size, action_size):
        super().__init__()
        self.features = nn.Sequential(
            nn.Linear(state_size, 256), nn.ReLU(),
            nn.Linear(256, 256),        nn.ReLU(),
        )
        self.value     = nn.Sequential(nn.Linear(256, 128), nn.ReLU(), nn.Linear(128, 1))
        self.advantage = nn.Sequential(nn.Linear(256, 128), nn.ReLU(), nn.Linear(128, action_size))

    def forward(self, x):
        f = self.features(x)
        v = self.value(f)
        a = self.advantage(f)
        return v + (a - a.mean(dim=1, keepdim=True))


class DQNAgent:
    def __init__(self, model_dir='models'):
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        print(f'裝置: {self.device}')
        if torch.cuda.is_available():
            print(f'GPU: {torch.cuda.get_device_name(0)}')

        self.policy_net  = DuelingDQN(STATE_SIZE, ACTION_SIZE).to(self.device)
        self.target_net  = DuelingDQN(STATE_SIZE, ACTION_SIZE).to(self.device)
        self.target_net.load_state_dict(self.policy_net.state_dict())
        self.target_net.eval()

        self.optimizer   = optim.Adam(self.policy_net.parameters(), lr=LR)
        self.scaler      = GradScaler('cuda') if torch.cuda.is_available() else None
        self.buffer      = ReplayBuffer(capacity=80000)
        self.epsilon:     float = EPSILON_START
        self.episode:     int   = 0
        self.total_steps: int   = 0
        self.model_dir   = Path(model_dir)
        self.model_dir.mkdir(exist_ok=True)

        params = sum(p.numel() for p in self.policy_net.parameters())
        print(f'Dueling DQN 參數量: {params:,}')

    def update_epsilon(self):
        self.epsilon = max(
            EPSILON_END,
            EPSILON_END + (EPSILON_START - EPSILON_END) *
            math.exp(-self.total_steps / EPSILON_DECAY_STEPS),
        )

    def get_action(self, state: np.ndarray) -> int:
        if np.random.rand() < self.epsilon:
            return np.random.randint(ACTION_SIZE)
        with torch.no_grad():
            s = torch.FloatTensor(state).unsqueeze(0).to(self.device)
            return self.policy_net(s).argmax().item()

    def train_step(self):
        if len(self.buffer) < BATCH_SIZE:
            return None
        states, actions, rewards, next_states, dones = self.buffer.sample(BATCH_SIZE)
        s  = torch.FloatTensor(states).to(self.device)
        a  = torch.LongTensor(actions).unsqueeze(1).to(self.device)
        r  = torch.FloatTensor(rewards).unsqueeze(1).to(self.device)
        s_ = torch.FloatTensor(next_states).to(self.device)
        d  = torch.FloatTensor(dones).unsqueeze(1).to(self.device)

        def compute():
            q = self.policy_net(s).gather(1, a)
            with torch.no_grad():
                best_a = self.policy_net(s_).argmax(1, keepdim=True)
                q_next = self.target_net(s_).gather(1, best_a)
                target = r + GAMMA * q_next * (1 - d)
            return F.smooth_l1_loss(q, target)

        if self.scaler:
            with autocast('cuda'):
                loss = compute()
            self.optimizer.zero_grad()
            self.scaler.scale(loss).backward()
            self.scaler.unscale_(self.optimizer)
            nn.utils.clip_grad_norm_(self.policy_net.parameters(), 10.0)
            self.scaler.step(self.optimizer)
            self.scaler.update()
        else:
            loss = compute()
            self.optimizer.zero_grad()
            loss.backward()
            nn.utils.clip_grad_norm_(self.policy_net.parameters(), 10.0)
            self.optimizer.step()

        for p, tp in zip(self.policy_net.parameters(), self.target_net.parameters()):
            tp.data.copy_(TAU * p.data + (1 - TAU) * tp.data)

        return loss.item()

    def end_episode(self):
        self.episode += 1

    def save(self, tag='latest'):
        path = self.model_dir / f'dqn_{tag}.pth'
        torch.save({
            'policy':      self.policy_net.state_dict(),
            'target':      self.target_net.state_dict(),
            'epsilon':     self.epsilon,
            'episode':     self.episode,
            'total_steps': self.total_steps,
        }, path)
        return path

    def load(self, tag='latest'):
        path = self.model_dir / f'dqn_{tag}.pth'
        if not path.exists():
            return False
        ckpt = torch.load(path, map_location=self.device, weights_only=False)
        self.policy_net.load_state_dict(ckpt['policy'])
        self.target_net.load_state_dict(ckpt['target'])
        self.epsilon     = ckpt['epsilon']
        self.episode     = ckpt['episode']
        self.total_steps = ckpt.get('total_steps', 0)
        print(f'載入 ep={self.episode}, steps={self.total_steps}, ε={self.epsilon:.3f}')
        return True
