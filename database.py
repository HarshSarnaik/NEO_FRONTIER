"""
database.py - FalkorDB Graph Setup & Synthetic 50-Node APT Network

Implements:
1. Official FalkorDB client connection.
2. Graph schema initialization with indexed nodes (Machine, User, Process).
3. 50-node synthetic network generation modeling benign corporate baseline
   and an embedded multi-stage APT (Advanced Persistent Threat) lateral movement path.
4. Highly optimized Cypher queries for sub-millisecond graph state extraction.
5. In-memory Mock fallback engine when Docker FalkorDB is offline (for testing).
"""

import sys
import logging
from typing import Dict, Any, List, Optional, Tuple

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("APTDatabase")

try:
    from falkordb import FalkorDB
    FALKORDB_AVAILABLE = True
except ImportError:
    FALKORDB_AVAILABLE = False
    logger.warning("falkordb module not installed. Running in mock mode.")


# ============================================================================
# Optimized Cypher Query Templates
# ============================================================================

CYPHER_GET_NODE_AND_NEIGHBORS = """
MATCH (n)
WHERE id(n) = $node_id
OPTIONAL MATCH (n)-[r]-(neighbor)
RETURN 
    id(n) AS curr_id,
    labels(n)[0] AS curr_type,
    properties(n) AS curr_props,
    collect({
        neighbor_id: id(neighbor),
        neighbor_type: labels(neighbor)[0],
        neighbor_props: properties(neighbor),
        rel_type: type(r),
        rel_props: properties(r)
    })[0..8] AS neighbors
"""

CYPHER_GET_ENTRY_NODES = """
MATCH (m:Machine)
RETURN id(m) AS id, m.ip AS ip, m.name AS name, m.compromised_status AS compromised_status
ORDER BY m.ip ASC
"""

CYPHER_GET_APT_GROUND_TRUTH = """
MATCH (n)
WHERE n.compromised_status = 1 OR n.compromised_status = true
RETURN id(n) AS id, labels(n)[0] AS type, properties(n) AS props
"""


# ============================================================================
# In-Memory Fallback Graph Engine (Mirroring FalkorDB Cypher Engine)
# ============================================================================

class MockQueryResult:
    def __init__(self, result_set: List[List[Any]], header: List[str]):
        self.result_set = result_set
        self.header = header

    def __iter__(self):
        return iter(self.result_set)

    def __len__(self):
        return len(self.result_set)


class MockFalkorGraph:
    """In-memory mock graph engine mimicking FalkorDB for offline CI/CD or local unit tests."""
    def __init__(self, name: str = "apt_hunt_graph"):
        self.name = name
        self.nodes: Dict[int, Dict[str, Any]] = {}
        self.edges: List[Dict[str, Any]] = []
        self._next_id = 0

    def query(self, cypher: str, params: Optional[Dict[str, Any]] = None) -> MockQueryResult:
        params = params or {}
        cypher_clean = cypher.strip()

        # Handle index creation (no-op in mock)
        if "CREATE INDEX" in cypher_clean:
            return MockQueryResult([], ["result"])

        # Handle MATCH (n) WHERE id(n) = $node_id OPTIONAL MATCH (n)-[r]-(neighbor)
        if "WHERE id(n) = $node_id" in cypher_clean or "WHERE id(curr) = $node_id" in cypher_clean:
            node_id = params.get("node_id")
            if node_id not in self.nodes:
                return MockQueryResult([], ["curr_id", "curr_type", "curr_props", "neighbors"])

            n = self.nodes[node_id]
            curr_id = node_id
            curr_type = n["label"]
            curr_props = n["props"]

            neighbors = []
            for edge in self.edges:
                neighbor_id = None
                rel_type = edge["type"]
                rel_props = edge["props"]

                if edge["src"] == node_id:
                    neighbor_id = edge["dst"]
                elif edge["dst"] == node_id:
                    neighbor_id = edge["src"]

                if neighbor_id is not None and neighbor_id in self.nodes:
                    nb = self.nodes[neighbor_id]
                    neighbors.append({
                        "neighbor_id": neighbor_id,
                        "neighbor_type": nb["label"],
                        "neighbor_props": nb["props"],
                        "rel_type": rel_type,
                        "rel_props": rel_props
                    })

            # Limit to 8 neighbors
            neighbors = neighbors[:8]
            return MockQueryResult([[curr_id, curr_type, curr_props, neighbors]], ["curr_id", "curr_type", "curr_props", "neighbors"])

        # Handle Entry Nodes query
        if "MATCH (m:Machine)" in cypher_clean and "compromised_status" in cypher_clean:
            records = []
            for nid, n in self.nodes.items():
                if n["label"] == "Machine":
                    records.append([
                        nid,
                        n["props"].get("ip", ""),
                        n["props"].get("name", ""),
                        n["props"].get("compromised_status", 0)
                    ])
            return MockQueryResult(records, ["id", "ip", "name", "compromised_status"])

        # Handle Ground Truth query
        if "WHERE n.compromised_status = 1" in cypher_clean:
            records = []
            for nid, n in self.nodes.items():
                if n["props"].get("compromised_status", 0) in (1, True):
                    records.append([nid, n["label"], n["props"]])
            return MockQueryResult(records, ["id", "type", "props"])

        return MockQueryResult([], ["result"])

    def create_node(self, label: str, props: Dict[str, Any]) -> int:
        nid = self._next_id
        self._next_id += 1
        self.nodes[nid] = {"label": label, "props": props}
        return nid

    def create_edge(self, src_id: int, dst_id: int, rel_type: str, props: Dict[str, Any]):
        self.edges.append({
            "src": src_id,
            "dst": dst_id,
            "type": rel_type,
            "props": props
        })


# ============================================================================
# FalkorDB Connection & Schema Setup
# ============================================================================

def get_falkor_client(host: str = "localhost", port: int = 6379, graph_name: str = "apt_hunt_graph", force_mock: bool = False):
    """
    Connects to FalkorDB Docker instance. If unavailable or force_mock=True,
    gracefully initializes MockFalkorGraph for seamless offline testing.
    """
    if force_mock or not FALKORDB_AVAILABLE:
        logger.info("Using MockFalkorGraph engine.")
        return MockFalkorGraph(name=graph_name)

    try:
        db = FalkorDB(host=host, port=port)
        # Test connection ping
        db.connection.ping()
        graph = db.select_graph(graph_name)
        logger.info(f"Connected successfully to FalkorDB on {host}:{port}, graph='{graph_name}'")
        return graph
    except Exception as e:
        logger.warning(f"Could not connect to FalkorDB at {host}:{port} ({e}). Falling back to MockFalkorGraph.")
        return MockFalkorGraph(name=graph_name)


def init_schema(graph: Any):
    """
    Creates indices on primary lookup keys for sub-millisecond RAM traversal.
    """
    logger.info("Initializing graph indices and constraints...")
    queries = [
        "CREATE INDEX FOR (m:Machine) ON (m.ip)",
        "CREATE INDEX FOR (m:Machine) ON (m.name)",
        "CREATE INDEX FOR (u:User) ON (u.username)",
        "CREATE INDEX FOR (p:Process) ON (p.pid)",
        "CREATE INDEX FOR (p:Process) ON (p.name)"
    ]
    for q in queries:
        try:
            graph.query(q)
        except Exception as e:
            # Index might already exist or mock engine
            pass
    logger.info("Schema indices initialized.")


# ============================================================================
# 50-Node Network Generation (Benign Baseline + Hidden APT Lateral Movement)
# ============================================================================

def populate_graph(graph: Any, reset: bool = True) -> Dict[str, Any]:
    """
    Generates a 50-node enterprise network:
      - 18 Machines (Workstations, DMZ Gateway, Application/DB Servers, Crown-Jewel Domain Controller)
      - 16 Users (Standard employees, Service accounts, Domain Admins)
      - 16 Processes (System services, Web servers, Malicious payloads)

    Embedded Threat Campaign:
      1. ws-03 (Linux, 10.0.1.13) [COMPROMISED]
      2. ws-03 -[:SPAWNED]-> c2_dropper (PID 4821) [COMPROMISED]
      3. c2_dropper -[:SPAWNED]-> priv_escalator (PID 4899) [COMPROMISED]
      4. priv_escalator -[:AUTHENTICATED_AS]-> svc_backup (Admin) [COMPROMISED]
      5. ws-03 -[:CONNECTED_TO {port: 445}]-> srv-file (Windows, 10.0.2.20) [COMPROMISED]
      6. srv-file -[:SPAWNED]-> beacon.exe (PID 5912) [COMPROMISED]
      7. beacon.exe -[:SPAWNED]-> mimikatz.exe (PID 6104) [COMPROMISED]
      8. mimikatz.exe -[:AUTHENTICATED_AS]-> domain_admin [COMPROMISED]
      9. srv-file -[:CONNECTED_TO {port: 3389}]-> srv-dc (10.0.0.1) [COMPROMISED - CROWN JEWEL]
      10. srv-dc -[:SPAWNED]-> exfil_agent.py (PID 7720) [COMPROMISED]

    All other nodes and edges represent legitimate corporate traffic baseline.
    """
    if isinstance(graph, MockFalkorGraph):
        if reset:
            graph.nodes.clear()
            graph.edges.clear()
            graph._next_id = 0
    else:
        if reset:
            try:
                graph.query("MATCH (n) DETACH DELETE n")
            except Exception:
                pass
        init_schema(graph)

    # 1. Define 18 Machines (ip, os, compromised_status, name)
    machines_def = [
        # Workstations (Subnet 10.0.1.0/24)
        {"name": "ws-01", "ip": "10.0.1.11", "os": "Windows", "compromised_status": 0},
        {"name": "ws-02", "ip": "10.0.1.12", "os": "Windows", "compromised_status": 0},
        {"name": "ws-03", "ip": "10.0.1.13", "os": "Linux",   "compromised_status": 1}, # APT Patient Zero
        {"name": "ws-04", "ip": "10.0.1.14", "os": "Windows", "compromised_status": 0},
        {"name": "ws-05", "ip": "10.0.1.15", "os": "Linux",   "compromised_status": 0},
        {"name": "ws-06", "ip": "10.0.1.16", "os": "Windows", "compromised_status": 0},
        {"name": "ws-07", "ip": "10.0.1.17", "os": "Windows", "compromised_status": 0},
        {"name": "ws-08", "ip": "10.0.1.18", "os": "Linux",   "compromised_status": 0},
        {"name": "ws-09", "ip": "10.0.1.19", "os": "Windows", "compromised_status": 0},
        {"name": "ws-10", "ip": "10.0.1.20", "os": "Windows", "compromised_status": 0},
        # DMZ Gateway
        {"name": "dmz-gw", "ip": "10.0.0.254", "os": "Linux", "compromised_status": 0},
        # Internal Servers (Subnet 10.0.2.0/24)
        {"name": "srv-web",    "ip": "10.0.2.10", "os": "Linux",   "compromised_status": 0},
        {"name": "srv-app",    "ip": "10.0.2.11", "os": "Linux",   "compromised_status": 0},
        {"name": "srv-db",     "ip": "10.0.2.12", "os": "Linux",   "compromised_status": 0},
        {"name": "srv-mail",   "ip": "10.0.2.13", "os": "Windows", "compromised_status": 0},
        {"name": "srv-file",   "ip": "10.0.2.20", "os": "Windows", "compromised_status": 1}, # APT Pivot Server
        {"name": "srv-backup", "ip": "10.0.2.25", "os": "Linux",   "compromised_status": 0},
        # Critical Crown Jewel
        {"name": "srv-dc",     "ip": "10.0.0.1",  "os": "Windows", "compromised_status": 1}, # APT Crown Jewel DC
    ]

    # 2. Define 16 Users (username, priv_level, compromised_status)
    users_def = [
        {"username": "alice",        "priv_level": "standard",     "compromised_status": 0},
        {"username": "bob",          "priv_level": "standard",     "compromised_status": 0},
        {"username": "charlie",      "priv_level": "standard",     "compromised_status": 0},
        {"username": "david",        "priv_level": "standard",     "compromised_status": 0},
        {"username": "eva",          "priv_level": "standard",     "compromised_status": 0},
        {"username": "frank",        "priv_level": "standard",     "compromised_status": 0},
        {"username": "grace",        "priv_level": "standard",     "compromised_status": 0},
        {"username": "heidi",        "priv_level": "standard",     "compromised_status": 0},
        {"username": "ivan",         "priv_level": "standard",     "compromised_status": 0},
        {"username": "judy",         "priv_level": "standard",     "compromised_status": 0},
        {"username": "svc_web",      "priv_level": "standard",     "compromised_status": 0},
        {"username": "svc_sql",      "priv_level": "admin",        "compromised_status": 0},
        {"username": "svc_backup",   "priv_level": "admin",        "compromised_status": 1}, # Compromised Privileged Account
        {"username": "sysadmin",     "priv_level": "admin",        "compromised_status": 0},
        {"username": "secops",       "priv_level": "admin",        "compromised_status": 0},
        {"username": "domain_admin", "priv_level": "domain_admin", "compromised_status": 1}, # Hijacked Domain Admin
    ]

    # 3. Define 16 Processes (name, pid, compromised_status)
    processes_def = [
        # Standard benign processes
        {"name": "systemd",         "pid": 1,    "compromised_status": 0},
        {"name": "sshd",            "pid": 842,  "compromised_status": 0},
        {"name": "nginx",           "pid": 1024, "compromised_status": 0},
        {"name": "mysqld",          "pid": 3306, "compromised_status": 0},
        {"name": "explorer.exe",    "pid": 2140, "compromised_status": 0},
        {"name": "svchost.exe",     "pid": 980,  "compromised_status": 0},
        {"name": "lsass.exe",       "pid": 652,  "compromised_status": 0},
        {"name": "cron",            "pid": 512,  "compromised_status": 0},
        {"name": "bash",            "pid": 1420, "compromised_status": 0},
        {"name": "powershell.exe",   "pid": 2980, "compromised_status": 0},
        {"name": "smbd",            "pid": 1120, "compromised_status": 0},
        # Hidden APT campaign processes
        {"name": "c2_dropper",      "pid": 4821, "compromised_status": 1},
        {"name": "priv_escalator",  "pid": 4899, "compromised_status": 1},
        {"name": "beacon.exe",      "pid": 5912, "compromised_status": 1},
        {"name": "mimikatz.exe",    "pid": 6104, "compromised_status": 1},
        {"name": "exfil_agent.py",  "pid": 7720, "compromised_status": 1},
    ]

    node_id_map: Dict[str, int] = {}

    if isinstance(graph, MockFalkorGraph):
        # Insert into mock
        for m in machines_def:
            nid = graph.create_node("Machine", m)
            node_id_map[m["name"]] = nid
        for u in users_def:
            nid = graph.create_node("User", u)
            node_id_map[u["username"]] = nid
        for p in processes_def:
            nid = graph.create_node("Process", p)
            node_id_map[p["name"]] = nid
    else:
        # Batch insert into FalkorDB
        for m in machines_def:
            res = graph.query("CREATE (n:Machine {ip: $ip, os: $os, compromised_status: $compromised_status, name: $name}) RETURN id(n) AS id", m)
            node_id_map[m["name"]] = res.result_set[0][0]
        for u in users_def:
            res = graph.query("CREATE (n:User {username: $username, priv_level: $priv_level, compromised_status: $compromised_status}) RETURN id(n) AS id", u)
            node_id_map[u["username"]] = res.result_set[0][0]
        for p in processes_def:
            res = graph.query("CREATE (n:Process {name: $name, pid: $pid, compromised_status: $compromised_status}) RETURN id(n) AS id", p)
            node_id_map[p["name"]] = res.result_set[0][0]

    # Helper function to add edge
    def add_edge(src_name: str, dst_name: str, rel_type: str, props: Optional[Dict[str, Any]] = None):
        props = props or {}
        src_id = node_id_map[src_name]
        dst_id = node_id_map[dst_name]
        if isinstance(graph, MockFalkorGraph):
            graph.create_edge(src_id, dst_id, rel_type, props)
        else:
            prop_str = ", ".join([f"{k}: ${k}" for k in props.keys()])
            rel_clause = f"[:{rel_type} {{{prop_str}}}]" if prop_str else f"[:{rel_type}]"
            query = f"""
            MATCH (a), (b)
            WHERE id(a) = $src_id AND id(b) = $dst_id
            CREATE (a)-{rel_clause}->(b)
            """
            params = {"src_id": src_id, "dst_id": dst_id, **props}
            graph.query(query, params)

    # 4. Populate Benign Baseline Connections (:CONNECTED_TO {port})
    benign_network_links = [
        ("ws-01", "srv-web", 80),  ("ws-02", "srv-web", 443),
        ("ws-04", "srv-file", 445), ("ws-05", "srv-app", 8080),
        ("ws-06", "srv-web", 443), ("ws-07", "srv-mail", 25),
        ("ws-08", "srv-file", 445), ("ws-09", "srv-app", 8080),
        ("ws-10", "srv-mail", 143), ("dmz-gw", "srv-web", 443),
        ("srv-app", "srv-db", 3306), ("srv-file", "srv-backup", 22),
        ("ws-01", "srv-dc", 389),   ("ws-02", "srv-dc", 389),
        ("ws-04", "srv-dc", 88),    ("ws-06", "srv-dc", 389)
    ]
    for src, dst, port in benign_network_links:
        add_edge(src, dst, "CONNECTED_TO", {"port": port})

    # 5. Populate Benign Process Spawns (:SPAWNED)
    benign_spawns = [
        ("ws-01", "explorer.exe"), ("ws-02", "explorer.exe"),
        ("ws-04", "powershell.exe"), ("ws-05", "bash"),
        ("srv-web", "nginx"), ("srv-db", "mysqld"),
        ("srv-mail", "svchost.exe"), ("dmz-gw", "sshd"),
        ("srv-dc", "lsass.exe"), ("srv-backup", "cron"),
        ("srv-file", "smbd"), ("ws-08", "systemd")
    ]
    for src, dst in benign_spawns:
        add_edge(src, dst, "SPAWNED")

    # 6. Populate Benign Authentications (:AUTHENTICATED_AS)
    benign_auths = [
        ("explorer.exe", "alice"), ("powershell.exe", "bob"),
        ("bash", "charlie"), ("nginx", "svc_web"),
        ("mysqld", "svc_sql"), ("sshd", "sysadmin"),
        ("lsass.exe", "secops"), ("smbd", "david"),
        ("cron", "svc_backup")
    ]
    for src, dst in benign_auths:
        add_edge(src, dst, "AUTHENTICATED_AS")

    # =========================================================================
    # 7. Embed the Hidden APT Lateral Movement Attack Path
    # =========================================================================
    # Stage 1 & 2: ws-03 executes dropper -> privilege escalator
    add_edge("ws-03", "c2_dropper", "SPAWNED")
    add_edge("c2_dropper", "priv_escalator", "SPAWNED")

    # Stage 3: Priv escalator hijacks svc_backup admin token
    add_edge("priv_escalator", "svc_backup", "AUTHENTICATED_AS")

    # Stage 4: Lateral Movement via SMB (Port 445) from ws-03 to srv-file
    add_edge("ws-03", "srv-file", "CONNECTED_TO", {"port": 445})

    # Stage 5 & 6: srv-file spawns beacon.exe -> mimikatz.exe
    add_edge("srv-file", "beacon.exe", "SPAWNED")
    add_edge("beacon.exe", "mimikatz.exe", "SPAWNED")

    # Stage 7: mimikatz dumps domain credentials, impersonates domain_admin
    add_edge("mimikatz.exe", "domain_admin", "AUTHENTICATED_AS")

    # Stage 8: Lateral Pivot via RDP (Port 3389) to Domain Controller (Crown Jewel)
    add_edge("srv-file", "srv-dc", "CONNECTED_TO", {"port": 3389})

    # Stage 9: srv-dc executes exfiltration payload
    add_edge("srv-dc", "exfil_agent.py", "SPAWNED")

    apt_path = [
        "ws-03", "c2_dropper", "priv_escalator", "svc_backup",
        "srv-file", "beacon.exe", "mimikatz.exe", "domain_admin",
        "srv-dc", "exfil_agent.py"
    ]
    apt_node_ids = {name: node_id_map[name] for name in apt_path}

    total_nodes = len(machines_def) + len(users_def) + len(processes_def)
    logger.info(f"Graph successfully populated with {total_nodes} nodes (18 Machines, 16 Users, 16 Processes).")
    logger.info(f"Hidden APT Lateral Movement Path embedded with {len(apt_path)} key nodes.")

    return {
        "total_nodes": total_nodes,
        "node_id_map": node_id_map,
        "apt_path_names": apt_path,
        "apt_node_ids": apt_node_ids
    }


def query_node_state(graph: Any, node_id: int) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Sub-millisecond query executing in RAM to retrieve the current node's attributes
    and its 1-hop connected neighbors.
    """
    result = graph.query(CYPHER_GET_NODE_AND_NEIGHBORS, {"node_id": node_id})
    if not result or len(result) == 0:
        return None, []

    record = result.result_set[0]
    curr_id = record[0]
    curr_type = record[1]
    curr_props = record[2] or {}
    raw_neighbors = record[3] or []

    current_node = {
        "id": curr_id,
        "type": curr_type,
        "props": curr_props
    }

    neighbors = []
    for nb in raw_neighbors:
        if nb and nb.get("neighbor_id") is not None:
            neighbors.append({
                "id": nb["neighbor_id"],
                "type": nb["neighbor_type"],
                "props": nb["neighbor_props"] or {},
                "rel_type": nb["rel_type"],
                "rel_props": nb["rel_props"] or {}
            })

    return current_node, neighbors


if __name__ == "__main__":
    logger.info("Running standalone database.py validation...")
    graph = get_falkor_client(force_mock=True)
    summary = populate_graph(graph, reset=True)
    print("\n--- Network Initialization Summary ---")
    print(f"Total Nodes: {summary['total_nodes']}")
    print(f"APT Path: {' -> '.join(summary['apt_path_names'])}")

    # Test Cypher Query on Patient Zero (ws-03)
    ws03_id = summary['node_id_map']['ws-03']
    curr, neighbors = query_node_state(graph, ws03_id)
    print(f"\nQueried Node: {curr['type']} {curr['props'].get('name', '')} (id={curr['id']}, compromised={curr['props'].get('compromised_status')})")
    print(f"Found {len(neighbors)} immediate neighbors:")
    for i, nb in enumerate(neighbors):
        print(f"  [{i}] ({nb['rel_type']}) -> {nb['type']} {nb['props'].get('name') or nb['props'].get('username')} (id={nb['id']})")
    print("\nDatabase module validated successfully!")
