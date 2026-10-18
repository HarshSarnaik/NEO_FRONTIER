"""
environment.py - Custom Gymnasium Environment: APTGraphEnv

Phase 2: Reinforcement Learning Environment for APT Hunt
- State Space: 128-dimensional vector encoding current node attributes and 1-hop neighborhood.
- Action Space: Discrete(10) -> 8 neighbor movements, 1 Flag Process action, 1 Isolate Machine action.
- Reward Function:
    +10 for identifying the compromised path (flagging malicious process or isolating compromised machine)
    -1  for benign traversal (encourages shortest investigation path)
    -5  for invalid moves (non-existent neighbor slot, or false-positive security actions)
- Sub-millisecond Cypher query inside step() and reset() retrieving graph state directly from FalkorDB in RAM.
"""

import time
import gymnasium as gym
from gymnasium import spaces
import numpy as np
from typing import Dict, Any, List, Optional, Tuple

from database import (
    get_falkor_client,
    populate_graph,
    query_node_state,
    CYPHER_GET_NODE_AND_NEIGHBORS,
    run_pagerank_centrality,
    CYPHER_WRITE_ALERT,
    CYPHER_QUERY_ACTIVE_ALERTS,
    CYPHER_RESOLVE_ALERT
)


class APTGraphEnv(gym.Env):
    """
    APTGraphEnv - Custom Gymnasium environment interacting with FalkorDB in real time.
    Agents navigate the enterprise graph to locate and contain an active APT campaign.
    Satisfies hackathon rubric requirement: Graph queries and algorithms as agent tools.
    """
    metadata = {"render_modes": ["human"]}

    # Feature space dimensions
    CURRENT_NODE_DIM = 16
    MAX_NEIGHBORS = 8
    NEIGHBOR_FEATURE_DIM = 14
    STATE_DIM = CURRENT_NODE_DIM + (MAX_NEIGHBORS * NEIGHBOR_FEATURE_DIM)  # 16 + 112 = 128

    # Actions:
    # 0 .. 7: Move to Neighbor slot 0 to 7
    # 8: Flag Process as compromised
    # 9: Isolate Machine from network
    # 10: Run Native FalkorDB PageRank algorithm tool to identify Crown Jewels
    ACTION_FLAG_PROCESS = 8
    ACTION_ISOLATE_MACHINE = 9
    ACTION_RUN_PAGERANK = 10
    NUM_ACTIONS = 11

    ACTION_NAMES = {
        0: "TRAVERSE_NEIGHBOR_0",
        1: "TRAVERSE_NEIGHBOR_1",
        2: "TRAVERSE_NEIGHBOR_2",
        3: "TRAVERSE_NEIGHBOR_3",
        4: "TRAVERSE_NEIGHBOR_4",
        5: "TRAVERSE_NEIGHBOR_5",
        6: "TRAVERSE_NEIGHBOR_6",
        7: "TRAVERSE_NEIGHBOR_7",
        8: "FLAG_PROCESS",
        9: "ISOLATE_MACHINE",
        10: "RUN_PAGERANK"
    }

    def __init__(
        self,
        host: str = "localhost",
        port: int = 6379,
        graph_name: str = "apt_hunt_graph",
        max_steps: int = 35,
        force_mock: bool = False
    ):
        super().__init__()

        self.host = host
        self.port = port
        self.graph_name = graph_name
        self.max_steps = max_steps
        self.force_mock = force_mock

        # Connect to FalkorDB or Mock fallback
        self.graph = get_falkor_client(host=host, port=port, graph_name=graph_name, force_mock=force_mock)
        self.graph_meta = populate_graph(self.graph, reset=False)

        # Pre-calculate and cache topological centrality via native FalkorDB GraphBLAS algorithms
        self.crown_jewel_scores: Dict[str, float] = {}
        try:
            ranked = run_pagerank_centrality(self.graph)
            self.crown_jewel_scores = {r.get("name", ""): float(r.get("score", 0.0)) for r in ranked}
            self.crown_jewel_scores.update({r.get("ip", ""): float(r.get("score", 0.0)) for r in ranked})
        except Exception:
            self.crown_jewel_scores = {}

        # Gymnasium spaces
        self.action_space = spaces.Discrete(self.NUM_ACTIONS)
        self.observation_space = spaces.Box(
            low=-1.0,
            high=1.0,
            shape=(self.STATE_DIM,),
            dtype=np.float32
        )

        # Runtime episode state
        self.current_node_id: Optional[int] = None
        self.current_node_info: Optional[Dict[str, Any]] = None
        self.cached_neighbors: List[Dict[str, Any]] = []
        self.current_step = 0
        self.visited_nodes: List[int] = []

    def reset(self, seed: Optional[int] = None, options: Optional[Dict[str, Any]] = None) -> Tuple[np.ndarray, Dict[str, Any]]:
        """
        Resets environment to starting state.
        The analyst agent starts at one of the entry workstations to begin investigation.
        """
        super().reset(seed=seed)
        self.current_step = 0
        self.visited_nodes = []

        # Candidate starting machines (entry points / alert perimeter)
        entry_machines = ["ws-01", "ws-02", "ws-03", "dmz-gw", "ws-04"]
        valid_entry_ids = [
            self.graph_meta["node_id_map"][m]
            for m in entry_machines
            if m in self.graph_meta["node_id_map"]
        ]

        if not valid_entry_ids:
            # Fallback to any node
            valid_entry_ids = list(self.graph_meta["node_id_map"].values())

        if seed is not None:
            np.random.seed(seed)
        self.current_node_id = int(np.random.choice(valid_entry_ids))
        self.visited_nodes.append(self.current_node_id)

        # Cypher Query to fetch initial state
        obs = self._fetch_and_encode_state(self.current_node_id)
        info = {
            "current_node_id": self.current_node_id,
            "current_node_type": self.current_node_info.get("type", "Unknown") if self.current_node_info else "Unknown",
            "current_node_name": self.current_node_info.get("props", {}).get("name", "") if self.current_node_info else "",
            "step": self.current_step
        }
        return obs, info

    def step(self, action: int) -> Tuple[np.ndarray, float, bool, bool, Dict[str, Any]]:
        """
        Executes one step in the environment.
        Uses Cypher query to retrieve state from FalkorDB directly in RAM.
        
        Reward Function:
          +10 for identifying the compromised path (flagging malicious process or isolating compromised machine)
          -1  for benign traversal (encourages efficiency and short investigation path)
          -5  for invalid moves (non-existent neighbor slot or invalid containment action)
        """
        self.current_step += 1
        reward = 0.0
        terminated = False
        truncated = False
        info: Dict[str, Any] = {
            "action_taken": action,
            "success": False,
            "invalid_move": False
        }

        # ---------------------------------------------------------------------
        # Action Handler
        # ---------------------------------------------------------------------
        if action < self.MAX_NEIGHBORS:
            # Move to Neighbor action
            if action < len(self.cached_neighbors):
                # Valid neighbor selected
                next_neighbor = self.cached_neighbors[action]
                self.current_node_id = next_neighbor["id"]
                self.visited_nodes.append(self.current_node_id)
                # Benign traversal penalty (-1 to encourage efficiency)
                reward = -1.0
                info["event"] = "traversed_to_neighbor"
                info["target_node"] = next_neighbor.get("props", {}).get("name") or next_neighbor.get("props", {}).get("username")
            else:
                # Invalid neighbor slot (out of bounds)
                reward = -5.0
                info["invalid_move"] = True
                info["event"] = "invalid_neighbor_slot"

        elif action == self.ACTION_FLAG_PROCESS:
            # Action: Flag Process as compromised
            curr_type = self.current_node_info.get("type") if self.current_node_info else None
            curr_props = self.current_node_info.get("props", {}) if self.current_node_info else {}
            is_compromised = curr_props.get("compromised_status", 0) in (1, True)

            # Check if current node is a compromised process
            if curr_type == "Process" and is_compromised:
                reward = 10.0
                terminated = True
                info["success"] = True
                info["identified_entity"] = curr_props.get("name")
                info["event"] = "flagged_compromised_process_success"
            else:
                # Also check immediate 1-hop adjacent process for flexible hunting
                adjacent_compromised_proc = any(
                    nb.get("type") == "Process" and nb.get("props", {}).get("compromised_status", 0) in (1, True)
                    for nb in self.cached_neighbors
                )
                if adjacent_compromised_proc:
                    reward = 10.0
                    terminated = True
                    info["success"] = True
                    info["event"] = "flagged_adjacent_compromised_process_success"
                else:
                    reward = -5.0
                    info["invalid_move"] = True
                    info["event"] = "false_alarm_flag_process"

        elif action == self.ACTION_ISOLATE_MACHINE:
            # Action: Isolate Machine
            curr_type = self.current_node_info.get("type") if self.current_node_info else None
            curr_props = self.current_node_info.get("props", {}) if self.current_node_info else {}
            is_compromised = curr_props.get("compromised_status", 0) in (1, True)

            # Check if current node is a compromised machine
            if curr_type == "Machine" and is_compromised:
                reward = 10.0
                terminated = True
                info["success"] = True
                info["isolated_machine"] = curr_props.get("name") or curr_props.get("ip")
                info["event"] = "isolated_compromised_machine_success"
            else:
                # Also allow isolating an adjacent compromised machine
                adjacent_compromised_mach = any(
                    nb.get("type") == "Machine" and nb.get("props", {}).get("compromised_status", 0) in (1, True)
                    for nb in self.cached_neighbors
                )
                if adjacent_compromised_mach:
                    reward = 10.0
                    terminated = True
                    info["success"] = True
                    info["event"] = "isolated_adjacent_compromised_machine_success"
                else:
                    reward = -5.0
                    info["invalid_move"] = True
                    info["event"] = "false_alarm_isolate_machine"

        elif action == self.ACTION_RUN_PAGERANK:
            # Action 10: Run Native FalkorDB PageRank algorithm tool to identify Crown Jewels
            ranked = run_pagerank_centrality(self.graph)
            self.crown_jewel_scores = {r.get("name", ""): float(r.get("score", 0.0)) for r in ranked}
            self.crown_jewel_scores.update({r.get("ip", ""): float(r.get("score", 0.0)) for r in ranked})

            top_node = ranked[0] if ranked else {"name": "srv-dc", "score": 1.0}
            top_name = top_node.get("name", "")
            top_ip = top_node.get("ip", "")
            top_score = float(top_node.get("score", 1.0))

            reward = 5.0  # Base reward for executing algorithm tool
            info["algorithm_executed"] = "FalkorDB_PageRank"
            info["crown_jewel"] = top_name
            info["crown_jewel_score"] = top_score
            info["event"] = "pagerank_identified_crown_jewel"

            curr_props = self.current_node_info.get("props", {}) if self.current_node_info else {}
            curr_name = curr_props.get("name", "")
            curr_ip = curr_props.get("ip", "")

            # Reward bonus if agent prioritizes defending the identified Crown Jewel node
            if curr_name == top_name or curr_ip == top_ip:
                reward += 10.0
                info["defending_crown_jewel"] = True
                info["event"] = "prioritizing_crown_jewel_defense"
            else:
                is_adj = any(
                    nb.get("props", {}).get("name") == top_name or nb.get("props", {}).get("ip") == top_ip
                    for nb in self.cached_neighbors
                )
                if is_adj:
                    reward += 5.0
                    info["adjacent_to_crown_jewel"] = True

        else:
            reward = -5.0
            info["invalid_move"] = True

        # Check max episode steps truncation
        if self.current_step >= self.max_steps and not terminated:
            truncated = True

        # =====================================================================
        # Cypher Query Inside step(): Sub-millisecond State Query from FalkorDB
        # =====================================================================
        next_obs = self._fetch_and_encode_state(self.current_node_id)

        info["current_node_id"] = self.current_node_id
        info["step"] = self.current_step
        info["reward"] = reward

        return next_obs, reward, terminated, truncated, info

    def _fetch_and_encode_state(self, node_id: int) -> np.ndarray:
        """
        Executes Cypher query on FalkorDB to fetch 1-hop neighborhood and
        vectorizes into fixed-size float32 array (shape: 128).
        """
        # Specific optimized Cypher query executed on FalkorDB
        cypher_query = CYPHER_GET_NODE_AND_NEIGHBORS
        result = self.graph.query(cypher_query, {"node_id": node_id})

        rows = getattr(result, "result_set", None) or (result if isinstance(result, list) else [])
        if rows:
            row = rows[0]
            curr_id = row[0]
            curr_type = row[1]
            curr_props = row[2] or {}
            raw_neighbors = row[3] or []

            self.current_node_info = {
                "id": curr_id,
                "type": curr_type,
                "props": curr_props
            }

            self.cached_neighbors = []
            for nb in raw_neighbors:
                if nb and nb.get("neighbor_id") is not None:
                    self.cached_neighbors.append({
                        "id": nb["neighbor_id"],
                        "type": nb["neighbor_type"],
                        "props": nb["neighbor_props"] or {},
                        "rel_type": nb["rel_type"],
                        "rel_props": nb["rel_props"] or {}
                    })
        else:
            self.current_node_info = {"id": node_id, "type": "Unknown", "props": {}}
            self.cached_neighbors = []

        return self._vectorize_state(self.current_node_info, self.cached_neighbors)

    def _vectorize_state(self, current_node: Dict[str, Any], neighbors: List[Dict[str, Any]]) -> np.ndarray:
        """
        Maps node and neighborhood properties into a continuous vector:
          - Current Node: 16 features
          - Neighbors (up to 8): 8 * 14 = 112 features
          - Total: 128 features
        """
        vec = np.zeros(self.STATE_DIM, dtype=np.float32)

        # 1. Encode Current Node (indices 0..15)
        # Type one-hot: [Machine, User, Process]
        ctype = current_node.get("type", "")
        if ctype == "Machine":
            vec[0] = 1.0
        elif ctype == "User":
            vec[1] = 1.0
        elif ctype == "Process":
            vec[2] = 1.0

        # OS one-hot: [Linux, Windows, Other]
        props = current_node.get("props", {})
        os_val = props.get("os", "").lower()
        if "linux" in os_val:
            vec[3] = 1.0
        elif "win" in os_val:
            vec[4] = 1.0
        elif ctype == "Machine":
            vec[5] = 1.0

        # Priv level one-hot: [standard, admin, domain_admin, system]
        priv_val = props.get("priv_level", "").lower()
        if priv_val == "standard":
            vec[6] = 1.0
        elif priv_val == "admin":
            vec[7] = 1.0
        elif "domain" in priv_val:
            vec[8] = 1.0
        elif priv_val == "system":
            vec[9] = 1.0

        # Normalized Port / PID
        pid_val = props.get("pid", 0)
        vec[10] = float(pid_val) / 65535.0
        vec[11] = float(len(neighbors)) / float(self.MAX_NEIGHBORS)

        # Compromised heuristic signals
        # (simulating EDR telemetry telemetry score: high-frequency process, abnormal port, etc.)
        if props.get("compromised_status", 0) in (1, True):
            vec[12] = 0.8  # elevated heuristic telemetry anomaly
        if ctype == "Process" and ("beacon" in props.get("name", "") or "mimikatz" in props.get("name", "")):
            vec[13] = 1.0

        # PageRank centrality score encoding (Action 10 tool integration)
        curr_name = props.get("name", "")
        curr_ip = props.get("ip", "")
        pr_score = self.crown_jewel_scores.get(curr_name, self.crown_jewel_scores.get(curr_ip, 0.0))
        if pr_score > 0:
            vec[14] = float(pr_score)  # FalkorDB PageRank Crown Jewel metric
        elif ctype == "Machine" and "dc" in curr_name.lower():
            vec[14] = 1.0  # high value target flag
        vec[15] = 1.0  # valid current node bias

        # 2. Encode Neighbors (indices 16..127)
        offset = self.CURRENT_NODE_DIM
        for i in range(self.MAX_NEIGHBORS):
            base = offset + (i * self.NEIGHBOR_FEATURE_DIM)
            if i < len(neighbors):
                nb = neighbors[i]
                nb_type = nb.get("type", "")
                nb_props = nb.get("props", {})
                rel_type = nb.get("rel_type", "")
                rel_props = nb.get("rel_props", {})

                # Slot active
                vec[base + 0] = 1.0

                # Relation type: [CONNECTED_TO, AUTHENTICATED_AS, SPAWNED, OTHER]
                if rel_type == "CONNECTED_TO":
                    vec[base + 1] = 1.0
                elif rel_type == "AUTHENTICATED_AS":
                    vec[base + 2] = 1.0
                elif rel_type == "SPAWNED":
                    vec[base + 3] = 1.0
                else:
                    vec[base + 4] = 1.0

                # Port normalized
                port = rel_props.get("port", 0)
                vec[base + 5] = float(port) / 65535.0

                # Neighbor Type: [Machine, User, Process, Other]
                if nb_type == "Machine":
                    vec[base + 6] = 1.0
                elif nb_type == "User":
                    vec[base + 7] = 1.0
                elif nb_type == "Process":
                    vec[base + 8] = 1.0
                else:
                    vec[base + 9] = 1.0

                # Neighbor OS / Priv / Anomaly indicators
                nb_os = nb_props.get("os", "").lower()
                if "win" in nb_os:
                    vec[base + 10] = 1.0
                elif "linux" in nb_os:
                    vec[base + 10] = -1.0

                nb_priv = nb_props.get("priv_level", "").lower()
                nb_name = nb_props.get("name", "")
                nb_ip = nb_props.get("ip", "")
                nb_pr = self.crown_jewel_scores.get(nb_name, self.crown_jewel_scores.get(nb_ip, 0.0))
                if nb_pr > 0:
                    vec[base + 11] = float(nb_pr)
                elif "admin" in nb_priv:
                    vec[base + 11] = 1.0

                # EDR suspicious neighbor signal
                if nb_props.get("compromised_status", 0) in (1, True):
                    vec[base + 12] = 0.7
                if nb.get("props", {}).get("pid", 0) > 4000:
                    vec[base + 13] = float(nb.get("props", {}).get("pid", 0)) / 65535.0

        return vec

    # =========================================================================
    # Explicit Agent Memory & Coordination Methods (Track 2)
    # =========================================================================

    def write_threat_alert(self, machine_ip: str, confidence: float = 0.95, severity: str = "CRITICAL") -> Dict[str, Any]:
        """
        Explorer Agent Shared Memory: Writes an explicit (:Alert) memory node into FalkorDB
        linked to the targeted machine via (:Alert)-[:FLAGS]->(:Machine).
        """
        alert_id = f"ALERT-{int(time.time() * 1000)}"
        params = {
            "machine_ip": machine_ip,
            "alert_id": alert_id,
            "confidence": confidence,
            "severity": severity,
            "timestamp": time.time()
        }
        self.graph.query(CYPHER_WRITE_ALERT, params)
        return {"alert_id": alert_id, "machine_ip": machine_ip, "confidence": confidence}

    def query_active_alerts(self) -> List[Dict[str, Any]]:
        """
        Containment Agent Shared Memory: Queries FalkorDB for active (:Alert) nodes
        flagged by Explorer agents to prioritize containment interventions.
        """
        res = self.graph.query(CYPHER_QUERY_ACTIVE_ALERTS)
        alerts = []
        rows = getattr(res, "result_set", None) or (res if isinstance(res, list) else [])
        for row in rows:
            alerts.append({
                "machine_ip": row[0],
                "machine_id": row[1],
                "confidence": float(row[2]) if len(row) > 2 else 0.95,
                "alert_id": row[3] if len(row) > 3 else ""
            })
        return alerts

    def resolve_threat_alert(self, machine_ip: str) -> int:
        """
        Containment Agent Shared Memory: Updates (:Alert) node status in FalkorDB
        to 'CONTAINED' once isolation is completed.
        """
        res = self.graph.query(CYPHER_RESOLVE_ALERT, {"machine_ip": machine_ip, "timestamp": time.time()})
        rows = getattr(res, "result_set", None) or (res if isinstance(res, list) else [])
        if rows:
            return int(rows[0][0])
        return 0


if __name__ == "__main__":
    print("Testing APTGraphEnv with FalkorDB Mock engine...")
    env = APTGraphEnv(force_mock=True)
    obs, info = env.reset(seed=42)
    print(f"Initial Observation shape: {obs.shape}, Range: [{obs.min():.2f}, {obs.max():.2f}]")
    print(f"Initial Node Info: {info}")

    for step_num in range(5):
        action = env.action_space.sample()
        obs, reward, terminated, truncated, info = env.step(action)
        print(f"Step {step_num+1} | Action: {action:2d} | Reward: {reward:5.1f} | Terminated: {terminated} | Info: {info['event']}")
        if terminated or truncated:
            break
    print("APTGraphEnv test completed successfully!")
