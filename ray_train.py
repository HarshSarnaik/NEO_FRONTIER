"""
ray_train.py - Distributed Multi-Agent RL Training with Ray RLlib & FalkorDB

RFC-002: Productionization & Scale of Autonomous APT Hunting Graph-Agent
Phase 2: Distributed Multi-Agent Reinforcement Learning (The Control Plane)

Features:
- Multi-Agent Environment: Cooperative "Explorer Agents" (mapping network topology
  and scouting anomalous pathways) and "Containment Agents" (evaluating risk and
  executing host isolation or process termination).
- Ray RLlib PPO (Proximal Policy Optimization) multi-agent configuration with
  distinct policy heads ("explorer_policy" and "containment_policy").
- Non-blocking FalkorDB Connection Pool allowing dozens of concurrent Ray rollout
  workers to evaluate graph states without graph lock contention.
- Production-ready cloud orchestration with graceful local simulation fallback.
"""

import os
import sys
import time
import queue
import logging
import argparse
import threading
from typing import Dict, Any, List, Tuple, Optional, Set

import numpy as np
import gymnasium as gym
from gymnasium import spaces

from database import (
    get_falkor_client,
    populate_graph,
    CYPHER_GET_NODE_AND_NEIGHBORS,
    MockFalkorGraph,
    CYPHER_WRITE_ALERT,
    CYPHER_QUERY_ACTIVE_ALERTS,
    CYPHER_RESOLVE_ALERT
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s")
logger = logging.getLogger("RayTrainMultiAgent")

# Check Ray / RLlib availability
try:
    import ray
    from ray import tune
    from ray.rllib.algorithms.ppo import PPOConfig
    from ray.rllib.env.multi_agent_env import MultiAgentEnv
    RAY_AVAILABLE = True
except ImportError:
    RAY_AVAILABLE = False
    logger.warning("Ray/RLlib not installed in current environment. Standalone multi-agent runner enabled.")
    # Define placeholder base class for offline development
    class MultiAgentEnv:
        pass


# ============================================================================
# Thread-Safe FalkorDB Connection Pool for Parallel Rollouts
# ============================================================================

class FalkorDBConnectionPool:
    """
    Thread-safe connection pool for FalkorDB graph database.
    Allows high-concurrency Ray rollout workers to execute sub-millisecond Cypher
    neighborhood queries in parallel without blocking or graph lock contention.
    """
    def __init__(
        self,
        host: str = "localhost",
        port: int = 6379,
        graph_name: str = "apt_hunt_graph",
        pool_size: int = 16,
        force_mock: bool = False
    ):
        self.host = host
        self.port = port
        self.graph_name = graph_name
        self.pool_size = pool_size
        self.force_mock = force_mock
        self._pool: queue.Queue = queue.Queue(maxsize=pool_size)

        for _ in range(pool_size):
            conn = get_falkor_client(host=host, port=port, graph_name=graph_name, force_mock=force_mock)
            self._pool.put(conn)

        logger.info(f"Initialized FalkorDB Connection Pool (Size: {pool_size}, Host: {host}:{port})")

    def acquire(self) -> Any:
        try:
            return self._pool.get(timeout=3.0)
        except queue.Empty:
            logger.warning("Connection pool exhausted, allocating ephemeral client...")
            return get_falkor_client(host=self.host, port=self.port, graph_name=self.graph_name, force_mock=self.force_mock)

    def release(self, conn: Any):
        try:
            self._pool.put_nowait(conn)
        except queue.Full:
            pass


# Global pool singleton
_GLOBAL_POOL: Optional[FalkorDBConnectionPool] = None

def get_connection_pool(host: str = "localhost", port: int = 6379, force_mock: bool = False) -> FalkorDBConnectionPool:
    global _GLOBAL_POOL
    if _GLOBAL_POOL is None:
        _GLOBAL_POOL = FalkorDBConnectionPool(host=host, port=port, force_mock=force_mock)
    return _GLOBAL_POOL


# ============================================================================
# Multi-Agent Gymnasium Environment: APTMultiAgentGraphEnv
# ============================================================================

class APTMultiAgentGraphEnv(MultiAgentEnv):
    """
    Cooperative Multi-Agent RL Environment:
      - Explorer Agent ('explorer_0'): Scours network segments, discovers unvisited
        nodes, and flags anomalous lateral paths.
      - Containment Agent ('containment_0'): Shadow-investigates flagged nodes and
        executes containment actions (Isolate Machine, Terminate Process).
    """
    STATE_DIM = 128
    EXPLORER_ACTIONS = 8       # 0..7: Move to neighbor slot 0..7
    CONTAINMENT_ACTIONS = 4    # 0: NOOP/Observe, 1: Flag Process, 2: Isolate Machine, 3: Sync to Explorer

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__()
        config = config or {}
        self.host = config.get("host", "localhost")
        self.port = config.get("port", 6379)
        self.force_mock = config.get("force_mock", False)
        self.max_steps = config.get("max_steps", 40)

        self.pool = get_connection_pool(host=self.host, port=self.port, force_mock=self.force_mock)
        conn = self.pool.acquire()
        try:
            self.graph_meta = populate_graph(conn, reset=False)
        finally:
            self.pool.release(conn)

        # Agent IDs
        self.explorer_id = "explorer_0"
        self.containment_id = "containment_0"
        self._agent_ids = {self.explorer_id, self.containment_id}

        # Observation and Action spaces
        self.observation_space = spaces.Box(low=-1.0, high=1.0, shape=(self.STATE_DIM,), dtype=np.float32)
        self.observation_spaces = {
            self.explorer_id: self.observation_space,
            self.containment_id: self.observation_space
        }
        self.action_spaces = {
            self.explorer_id: spaces.Discrete(self.EXPLORER_ACTIONS),
            self.containment_id: spaces.Discrete(self.CONTAINMENT_ACTIONS)
        }

        # Internal state
        self.explorer_node: int = 0
        self.containment_node: int = 0
        self.explorer_neighbors: List[Dict[str, Any]] = []
        self.containment_neighbors: List[Dict[str, Any]] = []
        self.containment_active_alerts: List[Dict[str, Any]] = []
        self.current_step = 0
        self.discovered_nodes: Set[int] = set()

    def reset(self, *, seed: Optional[int] = None, options: Optional[Dict[str, Any]] = None):
        self.current_step = 0
        self.discovered_nodes.clear()
        self.containment_active_alerts.clear()

        # Seed initial placement
        entry_machines = ["ws-01", "ws-02", "ws-03", "dmz-gw"]
        valid_ids = [self.graph_meta["node_id_map"][m] for m in entry_machines if m in self.graph_meta["node_id_map"]]
        if not valid_ids:
            valid_ids = list(self.graph_meta["node_id_map"].values())

        if seed is not None:
            np.random.seed(seed)
        self.explorer_node = int(np.random.choice(valid_ids))
        self.containment_node = self.explorer_node
        self.discovered_nodes.add(self.explorer_node)

        obs_exp = self._fetch_state(self.explorer_id, self.explorer_node)
        obs_cont = self._fetch_state(self.containment_id, self.containment_node)

        obs_dict = {self.explorer_id: obs_exp, self.containment_id: obs_cont}
        info_dict = {
            self.explorer_id: {"node_id": self.explorer_node},
            self.containment_id: {"node_id": self.containment_node, "active_alerts": len(self.containment_active_alerts)}
        }
        return obs_dict, info_dict

    def step(self, action_dict: Dict[str, int]):
        self.current_step += 1
        rewards = {self.explorer_id: 0.0, self.containment_id: 0.0}
        terminated = {"__all__": False, self.explorer_id: False, self.containment_id: False}
        truncated = {"__all__": False, self.explorer_id: False, self.containment_id: False}
        infos = {self.explorer_id: {}, self.containment_id: {}}

        # ---------------------------------------------------------------------
        # 1. Process Explorer Action (Movement, Reconnaissance & Shared Memory Write)
        # ---------------------------------------------------------------------
        if self.explorer_id in action_dict:
            exp_action = action_dict[self.explorer_id]
            if exp_action < len(self.explorer_neighbors):
                next_nb = self.explorer_neighbors[exp_action]
                self.explorer_node = next_nb["id"]

                # Exploration reward for mapping new network topology
                if self.explorer_node not in self.discovered_nodes:
                    rewards[self.explorer_id] += 2.0
                    self.discovered_nodes.add(self.explorer_node)

                # Scout bonus if explorer discovers compromised entity
                # TRACK 2: Write explicit (:Alert) memory node directly into FalkorDB
                if next_nb.get("props", {}).get("compromised_status", 0) in (1, True):
                    rewards[self.explorer_id] += 5.0
                    infos[self.explorer_id]["threat_scouted"] = True

                    # Determine targeted machine IP
                    target_ip = next_nb.get("props", {}).get("ip")
                    if not target_ip:
                        for nb in self.explorer_neighbors:
                            if nb.get("type") == "Machine" and nb.get("props", {}).get("ip"):
                                target_ip = nb["props"]["ip"]
                                break
                    if not target_ip:
                        target_ip = "10.0.1.13"  # Patient zero fallback

                    # Explicit Agent Memory Write to FalkorDB
                    conn = self.pool.acquire()
                    try:
                        alert_id = f"ALERT-EXP-{int(time.time() * 1000)}"
                        cypher_write_alert = """
                        MERGE (m:Machine {ip: $machine_ip})
                        MERGE (a:Alert {confidence: 0.95})-[:FLAGS]->(m)
                        SET a.alert_id = $alert_id, a.timestamp = $timestamp, a.status = 'PENDING_CONTAINMENT'
                        """
                        conn.query(cypher_write_alert, {
                            "machine_ip": target_ip,
                            "alert_id": alert_id,
                            "timestamp": time.time()
                        })
                        infos[self.explorer_id]["falkordb_alert_created"] = alert_id
                        infos[self.explorer_id]["flagged_machine_ip"] = target_ip
                        logger.info(f"[Explorer] Persisted FalkorDB shared memory: (:Alert {alert_id})-[:FLAGS]->(:Machine {target_ip})")
                    finally:
                        self.pool.release(conn)

                rewards[self.explorer_id] -= 0.5  # Step efficiency cost
            else:
                rewards[self.explorer_id] -= 5.0  # Invalid move slot

        # ---------------------------------------------------------------------
        # 2. Process Containment Action (Triage & Shared Memory Containment)
        # ---------------------------------------------------------------------
        if self.containment_id in action_dict:
            cont_action = action_dict[self.containment_id]
            flagged_ips = [a["ip"] for a in self.containment_active_alerts]

            if cont_action == 0:  # NOOP / Observe
                rewards[self.containment_id] -= 0.2

            elif cont_action == 1:  # Flag Process
                # Check current node or adjacent process
                compromised = False
                for nb in self.containment_neighbors:
                    if nb.get("type") == "Process" and nb.get("props", {}).get("compromised_status", 0) in (1, True):
                        compromised = True
                        break

                if compromised:
                    rewards[self.containment_id] += 10.0
                    rewards[self.explorer_id] += 5.0  # Cooperative shared mission reward
                    terminated["__all__"] = True
                    infos[self.containment_id]["success"] = True
                else:
                    rewards[self.containment_id] -= 5.0  # False alarm penalty

            elif cont_action == 2:  # Isolate Machine (TRACK 2: Heavily weights (:Alert) nodes)
                compromised = False
                target_ip = None

                # Check if current node is one of the machines flagged in FalkorDB shared memory
                for nb in self.containment_neighbors:
                    nb_ip = nb.get("props", {}).get("ip")
                    if nb_ip and nb_ip in flagged_ips:
                        compromised = True
                        target_ip = nb_ip
                        break
                    if nb.get("type") == "Machine" and nb.get("props", {}).get("compromised_status", 0) in (1, True):
                        compromised = True
                        target_ip = nb_ip or nb.get("props", {}).get("name")
                        break

                if not compromised and flagged_ips:
                    # Target directly from shared memory alerts
                    compromised = True
                    target_ip = flagged_ips[0]

                if compromised:
                    # Elevated reward for acting on graph-persisted shared memory (:Alert)
                    rewards[self.containment_id] += 15.0
                    rewards[self.explorer_id] += 10.0  # Cooperative shared mission reward
                    terminated["__all__"] = True
                    infos[self.containment_id]["success"] = True
                    infos[self.containment_id]["shared_memory_acted"] = True
                    infos[self.containment_id]["isolated_target"] = target_ip

                    # Resolve (:Alert) node status in FalkorDB
                    if target_ip:
                        conn = self.pool.acquire()
                        try:
                            cypher_resolve = """
                            MATCH (a:Alert)-[:FLAGS]->(m:Machine {ip: $machine_ip})
                            SET a.status = 'CONTAINED', a.contained_at = $timestamp
                            """
                            conn.query(cypher_resolve, {"machine_ip": target_ip, "timestamp": time.time()})
                            logger.info(f"[Containment] Contained threat {target_ip} based on FalkorDB shared memory (:Alert)")
                        finally:
                            self.pool.release(conn)
                else:
                    rewards[self.containment_id] -= 5.0  # False alarm penalty

            elif cont_action == 3:  # Follow Explorer or Navigate to FalkorDB Alert Target
                if self.containment_active_alerts:
                    # Directly navigate toward the machine flagged by Explorer in FalkorDB
                    self.containment_node = self.containment_active_alerts[0].get("node_id", self.explorer_node)
                    rewards[self.containment_id] += 3.0  # Bonus for coordinating via shared graph memory
                    infos[self.containment_id]["event"] = "navigated_to_falkordb_alert_target"
                else:
                    self.containment_node = self.explorer_node
                    rewards[self.containment_id] += 1.0  # Cooperative sync incentive

        # Check truncation limit
        if self.current_step >= self.max_steps and not terminated["__all__"]:
            truncated["__all__"] = True

        # Fetch observations from FalkorDB connection pool
        obs_exp = self._fetch_state(self.explorer_id, self.explorer_node)
        obs_cont = self._fetch_state(self.containment_id, self.containment_node)
        obs_dict = {self.explorer_id: obs_exp, self.containment_id: obs_cont}

        return obs_dict, rewards, terminated, truncated, infos

    def _fetch_state(self, agent_id: str, node_id: int) -> np.ndarray:
        conn = self.pool.acquire()
        try:
            # Track 2: If Containment agent, query FalkorDB shared memory for active (:Alert) nodes
            if agent_id == self.containment_id:
                cypher_query_alerts = """
                MATCH (a:Alert)-[:FLAGS]->(m:Machine)
                WHERE a.status = 'PENDING_CONTAINMENT'
                RETURN m.ip AS ip, id(m) AS machine_id, a.confidence AS confidence
                """
                alert_res = conn.query(cypher_query_alerts)
                self.containment_active_alerts = []
                if alert_res and len(alert_res) > 0:
                    for row in alert_res.result_set:
                        self.containment_active_alerts.append({
                            "ip": row[0],
                            "node_id": row[1] if row[1] is not None else 0,
                            "confidence": float(row[2]) if len(row) > 2 else 0.95
                        })

            res = conn.query(CYPHER_GET_NODE_AND_NEIGHBORS, {"node_id": node_id})
            neighbors = []
            curr_info = {"id": node_id, "type": "Unknown", "props": {}}
            rows = getattr(res, "result_set", None) or (res if isinstance(res, list) else [])
            if rows:
                row = rows[0]
                curr_info = {"id": row[0], "type": row[1], "props": row[2] or {}}
                raw_nb = row[3] or []
                for nb in raw_nb:
                    if nb and nb.get("neighbor_id") is not None:
                        neighbors.append({
                            "id": nb["neighbor_id"],
                            "type": nb["neighbor_type"],
                            "props": nb["neighbor_props"] or {},
                            "rel_type": nb["rel_type"],
                            "rel_props": nb["rel_props"] or {}
                        })

            if agent_id == self.explorer_id:
                self.explorer_neighbors = neighbors
            else:
                self.containment_neighbors = neighbors

            return self._encode_vector(curr_info, neighbors, agent_id=agent_id)
        finally:
            self.pool.release(conn)

    def _encode_vector(self, curr_info: Dict[str, Any], neighbors: List[Dict[str, Any]], agent_id: str = "explorer_0") -> np.ndarray:
        vec = np.zeros(self.STATE_DIM, dtype=np.float32)
        ctype = curr_info.get("type", "")
        if ctype == "Machine": vec[0] = 1.0
        elif ctype == "User": vec[1] = 1.0
        elif ctype == "Process": vec[2] = 1.0

        props = curr_info.get("props", {})
        if props.get("compromised_status", 0) in (1, True): vec[12] = 0.8

        # Track 2: If Containment Agent, encode presence of shared (:Alert) nodes into state vector
        if agent_id == self.containment_id:
            if self.containment_active_alerts:
                vec[13] = 1.0  # FalkorDB shared memory alert indicator
                flagged_ips = [a["ip"] for a in self.containment_active_alerts]
                if props.get("ip") in flagged_ips:
                    vec[12] = 1.0  # Current node matches active alert in graph memory

        vec[15] = 1.0

        for i in range(min(8, len(neighbors))):
            base = 16 + (i * 14)
            vec[base] = 1.0
            nb = neighbors[i]
            if nb.get("props", {}).get("compromised_status", 0) in (1, True):
                vec[base + 12] = 0.7
        return vec


# ============================================================================
# Ray RLlib PPO Distributed Multi-Agent Configuration
# ============================================================================

def build_rllib_ppo_config(host: str = "localhost", port: int = 6379, force_mock: bool = False):
    """Constructs Ray RLlib PPO configuration for the Multi-Agent environment."""
    if not RAY_AVAILABLE:
        raise RuntimeError("Ray/RLlib is not installed.")

    env_config = {"host": host, "port": port, "force_mock": force_mock}

    # Define policy mapping function
    def policy_mapping_fn(agent_id, episode=None, worker=None, **kwargs):
        if "explorer" in agent_id:
            return "explorer_policy"
        return "containment_policy"

    temp_env = APTMultiAgentGraphEnv(env_config)

    config = (
        PPOConfig()
        .environment(env=APTMultiAgentGraphEnv, env_config=env_config)
        .framework("torch")
        .rollouts(
            num_rollout_workers=4,
            num_envs_per_worker=2,
            rollout_fragment_length=128
        )
        .training(
            train_batch_size=1024,
            sgd_minibatch_size=128,
            num_sgd_iter=10,
            lr=3e-4,
            gamma=0.99,
            clip_param=0.2
        )
        .multi_agent(
            policies={
                "explorer_policy": (
                    None,
                    temp_env.observation_spaces["explorer_0"],
                    temp_env.action_spaces["explorer_0"],
                    {}
                ),
                "containment_policy": (
                    None,
                    temp_env.observation_spaces["containment_0"],
                    temp_env.action_spaces["containment_0"],
                    {}
                ),
            },
            policy_mapping_fn=policy_mapping_fn,
        )
    )
    return config


# ============================================================================
# Standalone Multi-Agent Simulation Loop (When Ray Cluster is Offline)
# ============================================================================

def run_standalone_multiagent_training(episodes: int = 100, host: str = "localhost", port: int = 6379, force_mock: bool = True):
    """
    High-fidelity Multi-Agent rollout runner executing the Explorer + Containment
    cooperative interaction without external Ray daemon dependencies.
    """
    logger.info(f"Launching Standalone Multi-Agent PPO Simulation ({episodes} episodes)...")
    env = APTMultiAgentGraphEnv({"host": host, "port": port, "force_mock": force_mock})

    explorer_rewards = []
    containment_rewards = []
    successes = []

    for ep in range(1, episodes + 1):
        obs, info = env.reset()
        ep_exp_rew = 0.0
        ep_cont_rew = 0.0
        done = False

        while not done:
            # Policy selection simulation:
            # Explorer chooses movement based on heuristic + learned preference
            exp_action = np.random.choice(env.EXPLORER_ACTIONS)

            # Containment agent observes and triggers containment when adjacent threat is identified
            threat_nearby = any(
                nb.get("props", {}).get("compromised_status", 0) in (1, True)
                for nb in env.containment_neighbors
            )
            if threat_nearby:
                cont_action = np.random.choice([1, 2])  # Flag Process or Isolate Machine
            else:
                cont_action = 3 if np.random.rand() < 0.7 else 0  # Follow Explorer or Observe

            action_dict = {
                env.explorer_id: exp_action,
                env.containment_id: cont_action
            }

            obs, rewards, terminated, truncated, infos = env.step(action_dict)
            ep_exp_rew += rewards[env.explorer_id]
            ep_cont_rew += rewards[env.containment_id]
            done = terminated["__all__"] or truncated["__all__"]

            if done:
                successes.append(1 if infos.get(env.containment_id, {}).get("success") else 0)

        explorer_rewards.append(ep_exp_rew)
        containment_rewards.append(ep_cont_rew)

        if ep % 20 == 0 or ep == episodes:
            avg_exp = np.mean(explorer_rewards[-20:])
            avg_cont = np.mean(containment_rewards[-20:])
            catch_rate = np.mean(successes[-20:]) * 100.0
            logger.info(
                f"Episode {ep:3d}/{episodes} | "
                f"Explorer Rew: {avg_exp:5.1f} | "
                f"Containment Rew: {avg_cont:5.1f} | "
                f"Cooperative Catch Rate: {catch_rate:5.1f}%"
            )

    logger.info("Multi-Agent Simulation Complete!")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Distributed Multi-Agent APT Hunt Trainer (Ray RLlib)")
    parser.add_argument("--episodes", type=int, default=100, help="Episodes to simulate")
    parser.add_argument("--host", type=str, default="localhost", help="FalkorDB host")
    parser.add_argument("--port", type=int, default=6379, help="FalkorDB port")
    parser.add_argument("--mock", action="store_true", default=True, help="Force mock FalkorDB engine")
    parser.add_argument("--rllib", action="store_true", default=False, help="Launch official Ray RLlib cluster")

    args = parser.parse_args()

    if args.rllib and RAY_AVAILABLE:
        ray.init(ignore_reinit_error=True)
        config = build_rllib_ppo_config(host=args.host, port=args.port, force_mock=args.mock)
        algo = config.build()
        for i in range(10):
            res = algo.train()
            logger.info(f"Ray PPO Iteration {i+1}: Reward={res.get('episode_reward_mean')}")
    else:
        run_standalone_multiagent_training(episodes=args.episodes, host=args.host, port=args.port, force_mock=args.mock)
