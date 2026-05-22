#!/usr/bin/env python3
"""Run a trained DQN policy (no exploration, no training).

Usage:
    source ~/dqn_env/bin/activate
    source ~/ros2_ws/install/setup.bash
    python3 ~/ros2_ws/src/turtlebot3_dqn/turtlebot3_dqn/run_policy.py
"""
import sys
from collections import deque
from pathlib import Path
import rclpy

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from turtlebot3_dqn.environment import TurtleBot3Env
from turtlebot3_dqn.dqn_agent import DQNAgent

MODEL_DIR    = Path(__file__).resolve().parent / 'models'
SMOOTH_TURNS = 3   # 連續幾次相同轉向才執行，避免左右振盪
STUCK_STEPS  = 20  # 幾步沒前進就強制後退
BACKUP_STEPS = 5   # 後退幾步


def smooth_action(action: int, history: deque) -> int:
    """若轉向動作不穩定（左右交替），強制改為前進。"""
    history.append(action)
    if len(history) < SMOOTH_TURNS:
        return action
    recent = list(history)[-SMOOTH_TURNS:]
    # 如果最近幾步都在轉但方向不一致 → 強制前進
    all_turns = all(a != 0 for a in recent)
    mixed     = len(set(recent)) > 1
    if all_turns and mixed:
        return 0  # 強制前進
    return action


def main():
    rclpy.init()
    env   = TurtleBot3Env()
    agent = DQNAgent(model_dir=str(MODEL_DIR))
    agent.epsilon = 0.0

    if not agent.load('best'):
        print('No trained model found. Train first with train.py')
        return

    print(f'Running trained policy (episode {agent.episode})...')
    print('Action smoothing ON — reduces oscillation')
    print('Press Ctrl+C to stop.\n')

    try:
        ep = 0
        while True:
            obs, _      = env.reset()
            total       = 0.0
            steps       = 0
            stuck_count = 0
            backup_left = 0
            action_hist = deque(maxlen=SMOOTH_TURNS + 2)

            while True:
                rclpy.spin_once(env, timeout_sec=0.0)

                # 強制後退（卡住時）
                if backup_left > 0:
                    obs, rew, terminated, truncated, _ = env.step(0)
                    env._publish_cmd(-0.10, 0.0)  # 直接覆蓋為後退
                    backup_left -= 1
                    total += rew
                    steps += 1
                    if terminated or truncated:
                        break
                    continue

                raw_action = agent.get_action(obs)
                action     = smooth_action(raw_action, action_hist)

                # 偵測卡住（一直轉但不前進）
                if action != 0:
                    stuck_count += 1
                else:
                    stuck_count = 0

                if stuck_count >= STUCK_STEPS:
                    stuck_count = 0
                    backup_left = BACKUP_STEPS
                    action_hist.clear()

                obs, rew, terminated, truncated, _ = env.step(action)
                total += rew
                steps += 1
                if terminated or truncated:
                    break

            ep += 1
            print(f'Episode {ep} | steps={steps} | reward={total:.1f}')
    except KeyboardInterrupt:
        pass
    finally:
        env.close()
        env.destroy_node()
        rclpy.shutdown()


if __name__ == '__main__':
    main()
