#!/usr/bin/env python3
"""DQN 訓練主程式 — 純避障版（規則固定）

Usage:
    source ~/.config/dds-monitor/credentials
    source ~/dqn_env/bin/activate
    source ~/ros2_ws/install/setup.bash
    python3 train.py
"""
import sys
import threading
import time
from pathlib import Path

import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import rclpy

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from turtlebot3_dqn.environment import TurtleBot3Env
from turtlebot3_dqn.dqn_agent   import DQNAgent, BATCH_SIZE

MAX_EPISODES   = 5000
SAVE_EVERY     = 50
TRAIN_PER_STEP = 4
LOG_DIR   = Path(__file__).resolve().parent / 'logs'
MODEL_DIR = Path(__file__).resolve().parent / 'models'
LOG_DIR.mkdir(exist_ok=True)


def plot_rewards(rewards, path):
    fig, axes = plt.subplots(1, 2, figsize=(16, 4))
    axes[0].plot(rewards, alpha=0.25, color='steelblue', label='reward')
    if len(rewards) >= 10:
        ma10 = np.convolve(rewards, np.ones(10) / 10, mode='valid')
        axes[0].plot(range(9, len(rewards)), ma10, color='orange', label='10-ep avg', lw=2)
    if len(rewards) >= 50:
        ma50 = np.convolve(rewards, np.ones(50) / 50, mode='valid')
        axes[0].plot(range(49, len(rewards)), ma50, color='red', label='50-ep avg', lw=2)
    axes[0].set(xlabel='Episode', ylabel='Total Reward', title='DQN Training Curve')
    axes[0].legend()

    tail   = rewards[-200:] if len(rewards) > 200 else rewards
    offset = max(0, len(rewards) - 200)
    axes[1].plot(range(offset, offset + len(tail)), tail, alpha=0.3, color='steelblue')
    if len(tail) >= 10:
        ma = np.convolve(tail, np.ones(10) / 10, mode='valid')
        axes[1].plot(range(offset + 9, offset + len(tail)), ma, color='orange', lw=2)
    axes[1].set(xlabel='Episode', title='Recent 200 Episodes')

    plt.tight_layout()
    plt.savefig(path, dpi=120)
    plt.close()


def gpu_train_loop(agent: DQNAgent, stop_event: threading.Event, steps_ref: list[int]):
    updates = 0
    while not stop_event.is_set():
        target = steps_ref[0] * TRAIN_PER_STEP
        if updates < target and len(agent.buffer) >= BATCH_SIZE:
            agent.train_step()
            updates += 1
            if updates % 10000 == 0:
                print(f'  [GPU] {updates} 次更新 | ε={agent.epsilon:.3f} | buf={len(agent.buffer)}')
        else:
            time.sleep(0.002)


def main():
    rclpy.init()
    env   = TurtleBot3Env()
    agent = DQNAgent(model_dir=str(MODEL_DIR))

    if agent.load('latest'):
        print(f'Resumed: ep={agent.episode}, ε={agent.epsilon:.3f}')

    rewards_log = LOG_DIR / 'rewards_history.npy'
    rewards     = list(np.load(rewards_log)) if rewards_log.exists() else []
    best_reward = max(rewards) if rewards else -float('inf')

    steps_ref: list[int] = [int(agent.total_steps)]
    stop_event   = threading.Event()
    train_thread = threading.Thread(
        target=gpu_train_loop, args=(agent, stop_event, steps_ref), daemon=True
    )
    train_thread.start()
    print(f'Double Dueling DQN | 純避障 | MAX_EP={MAX_EPISODES}\n')

    try:
        for ep in range(agent.episode, MAX_EPISODES):

            # 每 500 集 ε 反彈，防止局部最優解
            if ep > 0 and ep % 500 == 0:
                agent.epsilon = max(agent.epsilon, 0.25)
                print(f'  [探索重置] ep={ep}，ε={agent.epsilon:.2f}')

            # reset 直到起點安全
            for _ in range(5):
                try:
                    obs, _ = env.reset(episode=ep)
                except Exception as e:
                    print(f'  [WARN] reset: {e}')
                    continue
                if float(obs.min()) * 3.5 > 0.30:
                    break

            total_reward = 0.0
            ep_steps     = 0

            while True:
                rclpy.spin_once(env, timeout_sec=0.0)
                action = agent.get_action(obs)
                try:
                    next_obs, reward, terminated, truncated, _ = env.step(action)
                except Exception as e:
                    print(f'  [WARN] step: {e}')
                    break

                agent.buffer.push(obs, action, reward, next_obs, float(terminated))
                obs           = next_obs
                total_reward += reward
                ep_steps     += 1
                agent.total_steps += 1
                steps_ref[0]  = int(agent.total_steps)
                agent.update_epsilon()

                if terminated or truncated:
                    break

            agent.end_episode()
            rewards.append(total_reward)

            flag = '★' if total_reward > best_reward else ' '
            print(f'{flag}Ep {ep+1:4d} | steps={ep_steps:4d} | reward={total_reward:8.1f} | ε={agent.epsilon:.3f}')

            if total_reward > best_reward:
                best_reward = total_reward
                agent.save('best')

            if (ep + 1) % SAVE_EVERY == 0:
                agent.save('latest')
                np.save(rewards_log, np.array(rewards))
                plot_rewards(rewards, LOG_DIR / 'training_curve.png')
                print(f'  → Saved ep {ep+1} | best={best_reward:.1f}')

    except KeyboardInterrupt:
        print('\nInterrupted — saving...')
    finally:
        stop_event.set()
        train_thread.join(timeout=2.0)
        agent.save('latest')
        np.save(rewards_log, np.array(rewards))
        plot_rewards(rewards, LOG_DIR / 'training_curve.png')
        env.close()
        env.destroy_node()
        rclpy.shutdown()
        print(f'Done. Best={best_reward:.1f}')


if __name__ == '__main__':
    main()
