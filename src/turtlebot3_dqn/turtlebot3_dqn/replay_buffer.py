"""舊版 Dueling-DQN 訓練用的 replay buffer（保留作為早期版本歷史）。

TQC 訓練改用 stable-baselines3 內建 ReplayBuffer
（含 HER 支援與更高效的 numpy backend），本檔目前僅 dqn_agent.py 引用。
"""
import random
import threading
from collections import deque
import numpy as np


class ReplayBuffer:
    """Thread-safe FIFO replay buffer（同時用於 train.py 的多 worker 採樣）。"""

    def __init__(self, capacity=100000):
        self.buffer = deque(maxlen=capacity)
        self._lock  = threading.Lock()

    def push(self, state, action, reward, next_state, done):
        with self._lock:
            self.buffer.append((state, action, reward, next_state, done))

    def sample(self, batch_size):
        with self._lock:
            batch = random.sample(self.buffer, batch_size)
        states, actions, rewards, next_states, dones = zip(*batch)
        return (
            np.array(states,      dtype=np.float32),
            np.array(actions,     dtype=np.int64),
            np.array(rewards,     dtype=np.float32),
            np.array(next_states, dtype=np.float32),
            np.array(dones,       dtype=np.float32),
        )

    def __len__(self):
        with self._lock:
            return len(self.buffer)
