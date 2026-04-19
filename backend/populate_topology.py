"""
Populate network topology from existing database flows.
"""
import asyncio
from database import get_all_flows
from network_topology import NetworkTopology

async def populate_topology():
    topology = NetworkTopology()
    flows = await get_all_flows(1000)
    
    print(f"[Topology] Loading {len(flows)} flows into network graph...")
    
    for flow in flows:
        topology.add_flow(flow)
    
    print(f"[Topology] Graph built: {len(topology.graph.nodes)} nodes, {len(topology.graph.edges)} edges")
    print(f"[Topology] Suspicious nodes: {len(topology.suspicious_nodes)}")
    
    return topology

if __name__ == "__main__":
    topology = asyncio.run(populate_topology())
    print("\nTopology populated successfully!")
