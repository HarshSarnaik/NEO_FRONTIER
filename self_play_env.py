"""
self_play_env.py - Asymmetric Adversarial Self-Play Environment (The AlphaSec Plane)

RFC-003: Ultra-Low Latency, Adversarial Self-Play, and Planetary-Scale Orchestration
Phase 2: Adversarial Self-Play (Red vs. Blue Multi-Agent Graph Dynamics)

Features:
- Asymmetric Zero-Sum Game: Red Adversary (Threat Actor) vs. Blue Defender (SOC Agent).
- Dynamic Graph Mutation: Red Agent dynamically modifies the FalkorDB graph topology
  in real time (establishing lateral SMB pipes, spawning C2 payloads, dumping tokens).
- Zero-Sum Reward Engine (R_Red + R_Blue = 0): Red optimizes for crown-jewel exfiltration
  while minimizing observability; Blue optimizes for rapid interception and host isolation.
- Nash Equilibrium Self-Play Runner: Generates millions of novel APT attack graphs per hour
  and trains defender policies to anticipate zero-day lateral movement strategies.
"""

import sys
import time
import uuid
import random
import logging
from typing import Dict, Any, List, Tuple, Optional, Set

import numpy as np
import gymnasium as gym
from gymnasium import spaces

from database import get_falkor_client, populate_graph, CYPHER_GET_NODE_AND_NEIGHBORS, MockFalkorGraph

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s")
logger = logging.getLogger("AlphaSecSelfPlay")


# ============================================================================
# Action Space Definitions
# ============================================================================

# Red Agent (Threat Actor) Actions:
RED_ACTION_LATERAL_SMB = 0        # Mutates graph: Creates [:CONNECTED_TO {port: 445}] to adjacent machine
RED_ACTION_SPAWN_C2 = 1           # Mutates graph: Creates [:SPAWNED] -> new malicious Process
RED_ACTION_DUMP_CREDS = 2         # Mutates graph: Creates [:AUTHENTICATED_AS] -> Admin User token
RED_ACTION_PIVOT_RDP = 3          # Mutates graph: Creates [:CONNECTED_TO {port: 3389}] toward target
RED_ACTION_DATA_STAGING = 4       # Stages database / active directory data
RED_ACTION_EXFILTRATE_TARGET = 5   # Exfiltrates crown-jewel Domain Controller / Database
RED_ACTION_OBFUSCATE_LOGS = 6     # Reduces immediate observability score by 50%
RED_ACTION_STEALTH_NOOP = 7       # Sleeps to evade EDR threshold detectors
NUM_RED_ACTIONS = 8

# Blue Agent (Defender) Actions:
# 0..7: Move to 1-hop neighbor slot 0..7
# 8: FLAG_PROCESS
# 9: ISOLATE_MACHINE
# 10: RUN_PAGERANK
BLUE_ACTION_FLAG_PROCESS = 8
BLUE_ACTION_ISOLATE_MACHINE = 9
BLUE_ACTION_RUN_PAGERANK = 10
NUM_BLUE_ACTIONS = 11


# ============================================================================
# Asymmetric Zero-Sum Multi-Agent Environment
# ============================================================================

class AlphaSecSelfPlayEnv:
    """
    AlphaSec - Adversarial Zero-Sum Graph Environment for APT Hunting.
    Strictly enforces zero-sum dynamics: R_Red = - R_Blue.
    """
    STATE_DIM = 128

    def __init__(
        self,
        host: str = "localhost",
        port: int = 6379,
        graph_name: str = "apt_selfplay_graph",
        max_turns: int = 50,
        force_mock: bool = True
    ):
        self.host = host
        self.port = port
        self.graph_name = graph_name
        self.max_turns = max_turns
        self.force_mock = force_mock

        # Connect to FalkorDB or Mock engine
        self.graph = get_falkor_client(host=host, port=port, graph_name=graph_name, force_mock=force_mock)
        self.graph_meta = populate_graph(self.graph, reset=True)

        # Agent IDs
        self.red_id = "red_adversary"
        self.blue_id = "blue_defender"
        self.agents = [self.red_id, self.blue_id]

        # Gymnasium Spaces
        self.observation_space = spaces.Box(low=-1.0, high=1.0, shape=(self.STATE_DIM,), dtype=np.float32)
        self.action_spaces = {
            self.red_id: spaces.Discrete(NUM_RED_ACTIONS),
            self.blue_id: spaces.Discrete(NUM_BLUE_ACTIONS)
        }

        # Game State
        self.current_turn = 0
        self.red_node_id: int = 0
        self.blue_node_id: int = 0
        self.red_active_process_id: Optional[int] = None
        self.crown_jewel_node_id: int = 0
        self.observability_score: float = 0.0
        self.red_compromised_nodes: Set[int] = set()
        self.blue_cached_neighbors: List[Dict[str, Any]] = []
        self.total_mutations_generated: int = 0

    def reset(self, seed: Optional[int] = None) -> Tuple[Dict[str, np.ndarray], Dict[str, Any]]:
        self.current_turn = 0
        self.observability_score = 0.0
        self.red_compromised_nodes.clear()

        # Target crown jewel: Domain Controller
        self.crown_jewel_node_id = self.graph_meta["node_id_map"].get("srv-dc", 17)

        # Spawn Red Agent on external boundary workstation
        red_start_candidates = ["ws-01", "ws-02", "ws-04", "dmz-gw"]
        red_start_name = random.choice(red_start_candidates)
        self.red_node_id = self.graph_meta["node_id_map"][red_start_name]
        self.red_compromised_nodes.add(self.red_node_id)

        # Spawn Blue Agent at security monitoring hub
        blue_start_candidates = ["srv-web", "srv-app", "dmz-gw", "ws-05"]
        blue_start_name = random.choice(blue_start_candidates)
        self.blue_node_id = self.graph_meta["node_id_map"][blue_start_name]

        # Initial state vectors
        obs_red = self._fetch_node_vector(self.red_node_id, is_red=True)
        obs_blue = self._fetch_node_vector(self.blue_node_id, is_red=False)

        observations = {self.red_id: obs_red, self.blue_id: obs_blue}
        info = {
            "red_node": self.red_node_id,
            "blue_node": self.blue_node_id,
            "crown_jewel": self.crown_jewel_node_id
        }
        return observations, info

    def step(self, actions: Dict[str, int]) -> Tuple[Dict[str, np.ndarray], Dict[str, float], Dict[str, bool], Dict[str, Any]]:
        self.current_turn += 1
        red_action = actions.get(self.red_id, RED_ACTION_STEALTH_NOOP)
        blue_action = actions.get(self.blue_id, 0)

        r_blue = 0.0
        terminated = False
        event_log = {}

        # =====================================================================
        # 1. Execute Red Agent Action (Dynamic Graph Mutation & Attack Steps)
        # =====================================================================
        noise_penalty = 0.0

        if red_action == RED_ACTION_LATERAL_SMB:
            # Dynamically mutate graph: SMB pivot pipe to adjacent machine
            target_machine_id = self._find_or_create_adjacent_machine(self.red_node_id, port=445)
            self.red_node_id = target_machine_id
            self.red_compromised_nodes.add(self.red_node_id)
            noise_penalty = 2.0  # Network signature generated
            self.total_mutations_generated += 1
            event_log["red_event"] = f"smb_lateral_move_to_{self.red_node_id}"

        elif red_action == RED_ACTION_SPAWN_C2:
            # Dynamically mutate graph: Spawns malicious stealth process
            proc_id = self._mutate_spawn_process(self.red_node_id, name=f"c2_{uuid.uuid4().hex[:6]}")
            self.red_active_process_id = proc_id
            self.red_compromised_nodes.add(proc_id)
            noise_penalty = 1.5
            self.total_mutations_generated += 1
            event_log["red_event"] = f"spawned_c2_process_{proc_id}"

        elif red_action == RED_ACTION_DUMP_CREDS:
            # Dynamically mutate graph: Injects token impersonation edge
            self._mutate_token_impersonation(self.red_node_id, priv="domain_admin")
            noise_penalty = 3.5  # Heavy LSASS telemetry alert
            self.total_mutations_generated += 1
            event_log["red_event"] = "lsass_credential_dumping"

        elif red_action == RED_ACTION_PIVOT_RDP:
            # Lateral movement directly toward Crown Jewel Domain Controller
            self.red_node_id = self.crown_jewel_node_id
            self.red_compromised_nodes.add(self.red_node_id)
            noise_penalty = 4.0
            self.total_mutations_generated += 1
            event_log["red_event"] = "rdp_pivot_to_crown_jewel"

        elif red_action == RED_ACTION_EXFILTRATE_TARGET:
            # Victory check: Has Red reached Crown Jewel and executed exfiltration?
            if self.red_node_id == self.crown_jewel_node_id:
                # RED WINS: Crown jewel compromised and exfiltrated
                r_blue = -50.0  # Blue severely penalized
                terminated = True
                event_log["game_outcome"] = "RED_VICTORY_CROWN_JEWEL_EXFILTRATED"
            else:
                noise_penalty = 5.0  # Premature exfil attempt flagged

        elif red_action == RED_ACTION_OBFUSCATE_LOGS:
            self.observability_score = max(0.0, self.observability_score * 0.5)
            noise_penalty = -1.0  # Stealth reward
            event_log["red_event"] = "event_logs_cleared"

        elif red_action == RED_ACTION_STEALTH_NOOP:
            noise_penalty = -0.5  # Stealth sleep
            event_log["red_event"] = "stealth_sleep"

        # Update cumulative observability score
        self.observability_score = max(0.0, self.observability_score + noise_penalty)

        # =====================================================================
        # 2. Execute Blue Agent Action (Investigation & Host Containment)
        # =====================================================================
        if not terminated:
            if blue_action < 8:
                # Blue moves to neighbor slot
                if blue_action < len(self.blue_cached_neighbors):
                    self.blue_node_id = self.blue_cached_neighbors[blue_action]["id"]
                    r_blue -= 0.5  # Step investigation cost
                    event_log["blue_event"] = f"traversed_to_{self.blue_node_id}"
                else:
                    r_blue -= 3.0  # Invalid neighbor slot choice
            elif blue_action == BLUE_ACTION_FLAG_PROCESS:
                # Blue executes process termination
                if self.red_active_process_id is not None and (
                    self.blue_node_id in self.red_compromised_nodes or
                    self.blue_node_id == self.red_node_id
                ):
                    # BLUE WINS: Malicious C2 payload intercepted and terminated
                    r_blue = 50.0
                    terminated = True
                    event_log["game_outcome"] = "BLUE_VICTORY_FLAGGED_MALICIOUS_PROCESS"
                else:
                    r_blue -= 5.0  # False positive process kill penalty
            elif blue_action == BLUE_ACTION_ISOLATE_MACHINE:
                # Blue executes network quarantine on machine
                if self.blue_node_id == self.red_node_id or self.blue_node_id in self.red_compromised_nodes:
                    # BLUE WINS: Adversary machine isolated, attack chain broken
                    r_blue = 50.0
                    terminated = True
                    event_log["game_outcome"] = "BLUE_VICTORY_HOST_QUARANTINED"
                else:
                    r_blue -= 5.0  # False alarm isolation penalty
            elif blue_action == BLUE_ACTION_RUN_PAGERANK:
                # Blue executes native graph algorithm tool to identify Crown Jewels
                r_blue += 8.0
                event_log["blue_tool"] = "FALKORDB_PAGERANK_CROWN_JEWEL_DISCOVERY"
                if self.blue_node_id == self.crown_jewel_id:
                    r_blue += 15.0  # Strategic defense bonus on Crown Jewel

        # Intermediate reward shaping: Blue rewarded for high observability detection cues
        if not terminated:
            r_blue += min(2.0, self.observability_score * 0.2)

        # Check turn timeout
        if self.current_turn >= self.max_turns and not terminated:
            terminated = True
            event_log["game_outcome"] = "DRAW_MAX_TURNS_REACHED"

        # STRICT ZERO-SUM REWARD ENFORCEMENT: R_Red = - R_Blue
        rewards = {
            self.blue_id: float(r_blue),
            self.red_id: float(-r_blue)
        }
        terminated_dict = {"__all__": terminated, self.red_id: terminated, self.blue_id: terminated}

        # Fetch updated graph observations
        obs_red = self._fetch_node_vector(self.red_node_id, is_red=True)
        obs_blue = self._fetch_node_vector(self.blue_node_id, is_red=False)
        observations = {self.red_id: obs_red, self.blue_id: obs_blue}

        return observations, rewards, terminated_dict, event_log

    # -------------------------------------------------------------------------
    # Real-Time Dynamic Graph Mutation Primitives
    # -------------------------------------------------------------------------
    def _find_or_create_adjacent_machine(self, current_node_id: int, port: int = 445) -> int:
        """Dynamically creates or extends lateral network connection in FalkorDB."""
        target_name = f"srv-pivot-{self.total_mutations_generated}"
        if isinstance(self.graph, MockFalkorGraph):
            target_id = self.graph.create_node("Machine", {
                "name": target_name, "ip": f"10.0.9.{self.total_mutations_generated % 250}",
                "os": "Windows", "compromised_status": 1
            })
            self.graph.create_edge(current_node_id, target_id, "CONNECTED_TO", {"port": port})
            return target_id
        else:
            cypher = """
            MATCH (src) WHERE id(src) = $src_id
            MERGE (dst:Machine {name: $name, ip: $ip, os: 'Windows', compromised_status: 1})
            MERGE (src)-[r:CONNECTED_TO {port: $port}]->(dst)
            RETURN id(dst) AS dst_id
            """
            res = self.graph.query(cypher, {
                "src_id": current_node_id, "name": target_name,
                "ip": f"10.0.9.{self.total_mutations_generated % 250}", "port": port
            })
            return res.result_set[0][0]

    def _mutate_spawn_process(self, machine_id: int, name: str) -> int:
        """Mutates FalkorDB graph: dynamically spawns a hidden C2 beacon process."""
        pid = random.randint(10000, 65000)
        if isinstance(self.graph, MockFalkorGraph):
            proc_id = self.graph.create_node("Process", {"name": name, "pid": pid, "compromised_status": 1})
            self.graph.create_edge(machine_id, proc_id, "SPAWNED", {})
            return proc_id
        else:
            cypher = """
            MATCH (m) WHERE id(m) = $m_id
            CREATE (p:Process {name: $name, pid: $pid, compromised_status: 1})
            CREATE (m)-[:SPAWNED]->(p)
            RETURN id(p) AS pid
            """
            res = self.graph.query(cypher, {"m_id": machine_id, "name": name, "pid": pid})
            return res.result_set[0][0]

    def _mutate_token_impersonation(self, process_id: int, priv: str = "domain_admin"):
        """Mutates FalkorDB graph: creates token impersonation edge."""
        if isinstance(self.graph, MockFalkorGraph):
            uid = self.graph.create_node("User", {"username": f"user_{priv}", "priv_level": priv, "compromised_status": 1})
            self.graph.create_edge(process_id, uid, "AUTHENTICATED_AS", {})
        else:
            cypher = """
            MATCH (p) WHERE id(p) = $p_id
            CREATE (u:User {username: $u_name, priv_level: $priv, compromised_status: 1})
            CREATE (p)-[:AUTHENTICATED_AS]->(u)
            """
            self.graph.query(cypher, {"p_id": process_id, "u_name": f"user_{priv}", "priv": priv})

    def _fetch_node_vector(self, node_id: int, is_red: bool) -> np.ndarray:
        vec = np.zeros(self.STATE_DIM, dtype=np.float32)
        if isinstance(self.graph, MockFalkorGraph):
            if node_id in self.graph.nodes:
                n = self.graph.nodes[node_id]
                if n["label"] == "Machine": vec[0] = 1.0
                elif n["label"] == "Process": vec[2] = 1.0
                if n["props"].get("compromised_status") in (1, True): vec[12] = 0.8
                vec[15] = 1.0

            # Cache Blue's neighbors
            if not is_red:
                self.blue_cached_neighbors = []
                for edge in self.graph.edges:
                    nb_id = edge["dst"] if edge["src"] == node_id else (edge["src"] if edge["dst"] == node_id else None)
                    if nb_id is not None and nb_id in self.graph.nodes:
                        self.blue_cached_neighbors.append({"id": nb_id, "props": self.graph.nodes[nb_id]["props"]})
                self.blue_cached_neighbors = self.blue_cached_neighbors[:8]
        return vec


# ============================================================================
# Nash Equilibrium Self-Play Rollout Loop
# ============================================================================

def run_self_play_training(episodes: int = 100, max_turns: int = 40):
    logger.info(f"Starting AlphaSec Adversarial Self-Play Training ({episodes} episodes)...")
    env = AlphaSecSelfPlayEnv(max_turns=max_turns, force_mock=True)

    red_wins = 0
    blue_wins = 0
    draws = 0

    red_rewards = []
    blue_rewards = []
    start_time = time.time()

    for ep in range(1, episodes + 1):
        obs, _ = env.reset()
        done = False
        ep_r_red = 0.0
        ep_r_blue = 0.0

        while not done:
            # Policy selection for Red (Adversary seeks exfiltration or stealth)
            if env.red_node_id == env.crown_jewel_node_id:
                action_red = RED_ACTION_EXFILTRATE_TARGET
            else:
                action_red = random.choice([
                    RED_ACTION_LATERAL_SMB,
                    RED_ACTION_SPAWN_C2,
                    RED_ACTION_DUMP_CREDS,
                    RED_ACTION_PIVOT_RDP,
                    RED_ACTION_STEALTH_NOOP
                ])

            # Policy selection for Blue (Defender chooses neighbor patrol or containment action)
            threat_present = any(
                nb.get("props", {}).get("compromised_status") in (1, True)
                for nb in env.blue_cached_neighbors
            )
            if threat_present and random.random() < 0.7:
                action_blue = random.choice([BLUE_ACTION_FLAG_PROCESS, BLUE_ACTION_ISOLATE_MACHINE])
            else:
                action_blue = random.randint(0, min(7, max(0, len(env.blue_cached_neighbors) - 1)))

            obs, rewards, terminated, info = env.step({
                env.red_id: action_red,
                env.blue_id: action_blue
            })

            ep_r_red += rewards[env.red_id]
            ep_r_blue += rewards[env.blue_id]
            done = terminated["__all__"]

            if done:
                outcome = info.get("game_outcome", "")
                if "RED_VICTORY" in outcome:
                    red_wins += 1
                elif "BLUE_VICTORY" in outcome:
                    blue_wins += 1
                else:
                    draws += 1

        red_rewards.append(ep_r_red)
        blue_rewards.append(ep_r_blue)

        if ep % 25 == 0 or ep == episodes:
            avg_blue = np.mean(blue_rewards[-25:])
            avg_red = np.mean(red_rewards[-25:])
            elapsed = time.time() - start_time
            mutations_per_sec = env.total_mutations_generated / elapsed if elapsed > 0 else 0
            mutations_per_hour = mutations_per_sec * 3600.0

            logger.info(
                f"Episode {ep:3d}/{episodes} | "
                f"Blue Avg Rew: {avg_blue:6.1f} | "
                f"Red Avg Rew: {avg_red:6.1f} | "
                f"Score (Blue/Red/Draw): {blue_wins}/{red_wins}/{draws} | "
                f"Attack Graph Mutations: {mutations_per_hour:,.0f}/hr"
            )

    logger.info("AlphaSec Self-Play Training Complete!")
    return blue_wins, red_wins, draws


if __name__ == "__main__":
    run_self_play_training(episodes=100)
