"""
train.py - Deep Q-Network (DQN) Agent with SSD-Backed Experience Replay

Phase 3: Reinforcement Learning APT Hunter
- PyTorch Dueling Double DQN processing the 128-dimensional graph state vector.
- Custom SSD-backed Experience Replay Buffer using memory-mapped arrays (np.memmap)
  to eliminate RAM exhaustion by keeping only active state and sampled mini-batches in memory.
- 1,000-episode training loop with reward convergence tracking, detection rate logging,
  and convergence visualization plotting.
"""

import os
import sys
import time
import argparse
import logging
from pathlib import Path
from typing import Tuple, Dict, Any, List, Optional

import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
import matplotlib.pyplot as plt

from environment import APTGraphEnv

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("APTHunterTrain")


# ============================================================================
# SSD-Backed Memory-Mapped Experience Replay Buffer
# ============================================================================

class DiskExperienceReplayBuffer:
    """
    Disk-backed experience replay buffer utilizing np.memmap on SSD storage.
    
    Prevents RAM exhaustion during extended training runs by writing serialized
    transitions directly to SSD files. Only the active graph state and the sampled
    mini-batch are resident in RAM at any given moment.
    """
    def __init__(
        self,
        capacity: int = 100000,
        state_dim: int = 128,
        storage_dir: str = "./buffer_ssd_storage"
    ):
        self.capacity = capacity
        self.state_dim = state_dim
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)

        self.ptr = 0
        self.size = 0

        # Memory-mapped file paths on SSD
        self.states_path = self.storage_dir / "states.dat"
        self.actions_path = self.storage_dir / "actions.dat"
        self.rewards_path = self.storage_dir / "rewards.dat"
        self.next_states_path = self.storage_dir / "next_states.dat"
        self.dones_path = self.storage_dir / "dones.dat"

        # Initialize or attach memory-mapped arrays on SSD
        mode = "w+" if not self.states_path.exists() else "r+"
        self.states = np.memmap(self.states_path, dtype=np.float32, mode="w+", shape=(self.capacity, self.state_dim))
        self.actions = np.memmap(self.actions_path, dtype=np.int64, mode="w+", shape=(self.capacity, 1))
        self.rewards = np.memmap(self.rewards_path, dtype=np.float32, mode="w+", shape=(self.capacity, 1))
        self.next_states = np.memmap(self.next_states_path, dtype=np.float32, mode="w+", shape=(self.capacity, self.state_dim))
        self.dones = np.memmap(self.dones_path, dtype=np.float32, mode="w+", shape=(self.capacity, 1))

        logger.info(f"Initialized SSD Memory-Mapped Buffer at '{self.storage_dir}' (Capacity: {self.capacity:,} transitions)")

    def push(
        self,
        state: np.ndarray,
        action: int,
        reward: float,
        next_state: np.ndarray,
        done: bool
    ):
        """Writes a single transition directly through page cache to SSD storage."""
        idx = self.ptr
        self.states[idx] = state
        self.actions[idx] = action
        self.rewards[idx] = reward
        self.next_states[idx] = next_state
        self.dones[idx] = 1.0 if done else 0.0

        self.ptr = (self.ptr + 1) % self.capacity
        self.size = min(self.size + 1, self.capacity)

        # Periodic flush to commit physical pages to SSD disk
        if self.ptr % 500 == 0:
            self.flush()

    def sample(self, batch_size: int = 64) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        Samples a mini-batch of transitions directly from SSD.
        Only the batch_size rows are loaded into RAM.
        """
        assert self.size >= batch_size, f"Cannot sample {batch_size} from buffer of size {self.size}"

        indices = np.random.choice(self.size, size=batch_size, replace=False)

        batch_states = torch.as_tensor(self.states[indices], dtype=torch.float32)
        batch_actions = torch.as_tensor(self.actions[indices], dtype=torch.int64)
        batch_rewards = torch.as_tensor(self.rewards[indices], dtype=torch.float32)
        batch_next_states = torch.as_tensor(self.next_states[indices], dtype=torch.float32)
        batch_dones = torch.as_tensor(self.dones[indices], dtype=torch.float32)

        return batch_states, batch_actions, batch_rewards, batch_next_states, batch_dones

    def flush(self):
        """Flushes in-memory pages to persistent SSD storage."""
        self.states.flush()
        self.actions.flush()
        self.rewards.flush()
        self.next_states.flush()
        self.dones.flush()

    def get_disk_usage_mb(self) -> float:
        """Calculates total disk footprint of the buffer on SSD in Megabytes."""
        total_bytes = 0
        for f in [self.states_path, self.actions_path, self.rewards_path, self.next_states_path, self.dones_path]:
            if f.exists():
                total_bytes += f.stat().st_size
        return total_bytes / (1024 * 1024)

    def __len__(self):
        return self.size


# ============================================================================
# PyTorch Dueling Q-Network
# ============================================================================

class DuelingDQN(nn.Module):
    """
    Dueling Deep Q-Network for graph-based APT hunting.
    Decomposes Q(s, a) into state Value V(s) and action Advantage A(s, a)
    to stabilize policy learning across large sparse graph topologies.
    """
    def __init__(self, state_dim: int = 128, action_dim: int = 10):
        super().__init__()

        # Feature representation backbone
        self.feature_extractor = nn.Sequential(
            nn.Linear(state_dim, 256),
            nn.LayerNorm(256),
            nn.ReLU(),
            nn.Linear(256, 256),
            nn.LayerNorm(256),
            nn.ReLU()
        )

        # Value stream: V(s)
        self.value_stream = nn.Sequential(
            nn.Linear(256, 128),
            nn.ReLU(),
            nn.Linear(128, 1)
        )

        # Advantage stream: A(s, a)
        self.advantage_stream = nn.Sequential(
            nn.Linear(256, 128),
            nn.ReLU(),
            nn.Linear(128, action_dim)
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        features = self.feature_extractor(x)
        val = self.value_stream(features)
        adv = self.advantage_stream(features)
        # Q(s, a) = V(s) + (A(s, a) - mean(A(s, a')))
        q_values = val + (adv - adv.mean(dim=-1, keepdim=True))
        return q_values


# ============================================================================
# DQN Agent with Double-Q Updates & Target Polyak Averaging
# ============================================================================

class DQNAgent:
    def __init__(
        self,
        state_dim: int = 128,
        action_dim: int = 10,
        lr: float = 3e-4,
        gamma: float = 0.99,
        tau: float = 0.005,
        device: Optional[str] = None
    ):
        self.state_dim = state_dim
        self.action_dim = action_dim
        self.gamma = gamma
        self.tau = tau

        if device:
            self.device = torch.device(device)
        else:
            self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

        # Online network & Target network
        self.policy_net = DuelingDQN(state_dim, action_dim).to(self.device)
        self.target_net = DuelingDQN(state_dim, action_dim).to(self.device)
        self.target_net.load_state_dict(self.policy_net.state_dict())
        self.target_net.eval()

        self.optimizer = optim.AdamW(self.policy_net.parameters(), lr=lr, weight_decay=1e-5)
        self.criterion = nn.SmoothL1Loss()  # Huber Loss for robust gradients

    def select_action(self, state: np.ndarray, epsilon: float = 0.0) -> int:
        if np.random.rand() < epsilon:
            return int(np.random.randint(self.action_dim))

        state_tensor = torch.as_tensor(state, dtype=torch.float32, device=self.device).unsqueeze(0)
        with torch.no_grad():
            q_values = self.policy_net(state_tensor)
            return int(q_values.argmax(dim=-1).item())

    def update(self, buffer: DiskExperienceReplayBuffer, batch_size: int = 64) -> float:
        if len(buffer) < batch_size:
            return 0.0

        states, actions, rewards, next_states, dones = buffer.sample(batch_size)
        states = states.to(self.device)
        actions = actions.to(self.device)
        rewards = rewards.to(self.device)
        next_states = next_states.to(self.device)
        dones = dones.to(self.device)

        # Current Q-values: Q(s, a)
        curr_q = self.policy_net(states).gather(1, actions)

        # Double DQN target computation:
        # 1. Best action from online policy net: a* = argmax_a Q_online(s', a)
        # 2. Q-value evaluated by target net: Q_target(s', a*)
        with torch.no_grad():
            next_actions = self.policy_net(next_states).argmax(dim=-1, keepdim=True)
            next_q = self.target_net(next_states).gather(1, next_actions)
            target_q = rewards + (1.0 - dones) * self.gamma * next_q

        loss = self.criterion(curr_q, target_q)

        self.optimizer.zero_grad()
        loss.backward()
        # Gradient clipping to prevent exploding gradients
        torch.nn.utils.clip_grad_norm_(self.policy_net.parameters(), max_norm=10.0)
        self.optimizer.step()

        # Polyak soft update of target network
        for target_param, policy_param in zip(self.target_net.parameters(), self.policy_net.parameters()):
            target_param.data.copy_(self.tau * policy_param.data + (1.0 - self.tau) * target_param.data)

        return float(loss.item())


# ============================================================================
# Training Loop & Convergence Metrics Logging
# ============================================================================

def train_apt_agent(
    episodes: int = 1000,
    batch_size: int = 64,
    learning_rate: float = 3e-4,
    buffer_capacity: int = 100000,
    epsilon_start: float = 1.0,
    epsilon_end: float = 0.05,
    epsilon_decay: float = 0.995,
    host: str = "localhost",
    port: int = 6379,
    force_mock: bool = False,
    save_dir: str = "./checkpoints",
    plot_file: str = "reward_convergence.png"
):
    os.makedirs(save_dir, exist_ok=True)

    # Initialize FalkorDB Gymnasium environment
    env = APTGraphEnv(host=host, port=port, force_mock=force_mock)
    agent = DQNAgent(state_dim=env.STATE_DIM, action_dim=env.NUM_ACTIONS, lr=learning_rate)
    buffer = DiskExperienceReplayBuffer(capacity=buffer_capacity, state_dim=env.STATE_DIM)

    epsilon = epsilon_start

    # Metrics history
    rewards_history: List[float] = []
    lengths_history: List[int] = []
    success_history: List[int] = []
    losses_history: List[float] = []

    start_time = time.time()
    logger.info(f"Starting APT Hunt Training for {episodes} episodes on device: {agent.device}...")

    for ep in range(1, episodes + 1):
        obs, info = env.reset()
        ep_reward = 0.0
        ep_steps = 0
        ep_losses = []
        done = False

        while not done:
            action = agent.select_action(obs, epsilon=epsilon)
            next_obs, reward, terminated, truncated, step_info = env.step(action)
            done = terminated or truncated

            # Push transition directly to SSD
            buffer.push(obs, action, reward, next_obs, terminated)

            # Gradient descent step
            if len(buffer) >= batch_size:
                loss = agent.update(buffer, batch_size)
                ep_losses.append(loss)

            obs = next_obs
            ep_reward += reward
            ep_steps += 1

            if done:
                success_flag = 1 if step_info.get("success", False) else 0
                success_history.append(success_flag)

        # Decay exploration rate
        epsilon = max(epsilon_end, epsilon * epsilon_decay)

        rewards_history.append(ep_reward)
        lengths_history.append(ep_steps)
        if ep_losses:
            losses_history.append(float(np.mean(ep_losses)))

        # Periodic logging every 50 episodes
        if ep % 50 == 0 or ep == episodes:
            avg_reward = np.mean(rewards_history[-50:])
            avg_length = np.mean(lengths_history[-50:])
            recent_success = np.mean(success_history[-50:]) * 100.0
            recent_loss = np.mean(losses_history[-50:]) if losses_history else 0.0
            disk_mb = buffer.get_disk_usage_mb()
            elapsed = time.time() - start_time

            logger.info(
                f"Episode {ep:4d}/{episodes} | "
                f"Avg Reward: {avg_reward:6.2f} | "
                f"Avg Steps: {avg_length:4.1f} | "
                f"APT Catch Rate: {recent_success:5.1f}% | "
                f"Loss: {recent_loss:.4f} | "
                f"Epsilon: {epsilon:.3f} | "
                f"SSD Buffer: {disk_mb:.1f} MB | "
                f"Elapsed: {elapsed:.1f}s"
            )

    # Flush all remaining writes to SSD
    buffer.flush()

    # Save trained PyTorch model
    checkpoint_path = os.path.join(save_dir, "apt_dqn_agent.pt")
    torch.save({
        "policy_net": agent.policy_net.state_dict(),
        "target_net": agent.target_net.state_dict(),
        "optimizer": agent.optimizer.state_dict(),
        "episodes": episodes,
        "final_reward": rewards_history[-1]
    }, checkpoint_path)
    logger.info(f"Model checkpoint saved successfully to {checkpoint_path}")

    # Plot Reward Convergence and Evaluation Metrics
    plot_convergence(rewards_history, lengths_history, success_history, plot_file)
    logger.info("Training complete!")

    return rewards_history, success_history


def plot_convergence(rewards: List[float], lengths: List[int], successes: List[int], filename: str):
    """Generates and saves convergence visualization plots."""
    episodes = range(1, len(rewards) + 1)
    window = 50
    rolling_rewards = [np.mean(rewards[max(0, i - window):i + 1]) for i in range(len(rewards))]
    rolling_success = [np.mean(successes[max(0, i - window):i + 1]) * 100.0 for i in range(len(successes))]

    fig, (ax1, ax2, ax3) = plt.subplots(3, 1, figsize=(10, 12), sharex=True)

    # 1. Episode Reward Convergence
    ax1.plot(episodes, rewards, color="#1f77b4", alpha=0.25, label="Raw Episode Reward")
    ax1.plot(episodes, rolling_rewards, color="#0052cc", linewidth=2.0, label="50-Episode Moving Avg")
    ax1.axhline(0, color="gray", linestyle="--", alpha=0.6)
    ax1.set_ylabel("Reward", fontsize=11, fontweight="bold")
    ax1.set_title("APT Hunting Agent: Reward Convergence (DQN + FalkorDB)", fontsize=13, fontweight="bold")
    ax1.grid(True, linestyle=":", alpha=0.6)
    ax1.legend(loc="lower right")

    # 2. APT Detection & Containment Success Rate
    ax2.plot(episodes, rolling_success, color="#2ca02c", linewidth=2.0, label="APT Detection Rate (%)")
    ax2.set_ylabel("Success Rate (%)", fontsize=11, fontweight="bold")
    ax2.set_ylim(-5, 105)
    ax2.grid(True, linestyle=":", alpha=0.6)
    ax2.legend(loc="upper left")

    # 3. Investigation Path Efficiency (Episode Length)
    rolling_lengths = [np.mean(lengths[max(0, i - window):i + 1]) for i in range(len(lengths))]
    ax3.plot(episodes, rolling_lengths, color="#d62728", linewidth=1.8, label="Steps to Containment")
    ax3.set_xlabel("Training Episodes", fontsize=11, fontweight="bold")
    ax3.set_ylabel("Steps", fontsize=11, fontweight="bold")
    ax3.grid(True, linestyle=":", alpha=0.6)
    ax3.legend(loc="upper right")

    plt.tight_layout()
    plt.savefig(filename, dpi=150)
    plt.close()
    logger.info(f"Convergence metrics plot saved to {filename}")


# ============================================================================
# CLI Entrypoint
# ============================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train PyTorch DQN APT Hunting Agent on FalkorDB Graph")
    parser.add_argument("--episodes", type=int, default=1000, help="Number of training episodes (default: 1000)")
    parser.add_argument("--batch-size", type=int, default=64, help="Mini-batch size (default: 64)")
    parser.add_argument("--lr", type=float, default=3e-4, help="Learning rate (default: 0.0003)")
    parser.add_argument("--host", type=str, default="localhost", help="FalkorDB host (default: localhost)")
    parser.add_argument("--port", type=int, default=6379, help="FalkorDB port (default: 6379)")
    parser.add_argument("--mock", action="store_true", default=False, help="Force mock FalkorDB engine")
    parser.add_argument("--plot", type=str, default="reward_convergence.png", help="Output convergence plot file")

    args = parser.parse_args()

    train_apt_agent(
        episodes=args.episodes,
        batch_size=args.batch_size,
        learning_rate=args.lr,
        host=args.host,
        port=args.port,
        force_mock=args.mock,
        plot_file=args.plot
    )
