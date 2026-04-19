"""
Network topology visualization and graph analysis.
Builds real-time network graph with community detection and centrality metrics.
"""

from __future__ import annotations

import networkx as nx
from collections import defaultdict
from typing import Dict, List, Tuple
import community as community_louvain


class NetworkTopology:
    """Network graph builder and analyzer."""

    def __init__(self):
        self.graph = nx.DiGraph()
        self.flow_count = defaultdict(int)
        self.suspicious_nodes = set()

    def add_flow(self, flow: Dict):
        """Add flow to network graph."""
        src = flow["src_ip"]
        dst = flow["dst_ip"]
        
        # Add nodes
        self.graph.add_node(src, type="host")
        self.graph.add_node(dst, type="host")
        
        # Add/update edge
        if self.graph.has_edge(src, dst):
            self.graph[src][dst]["weight"] += 1
            self.graph[src][dst]["flows"].append(flow["flow_id"])
        else:
            self.graph.add_edge(src, dst, weight=1, flows=[flow["flow_id"]])
        
        self.flow_count[(src, dst)] += 1
        
        # Mark suspicious nodes
        if flow.get("is_anomaly", 0) == 1:
            self.suspicious_nodes.add(src)
            self.suspicious_nodes.add(dst)

    def get_centrality_metrics(self) -> Dict[str, Dict]:
        """Calculate node centrality metrics."""
        if len(self.graph.nodes) == 0:
            return {}
        
        degree_cent = nx.degree_centrality(self.graph)
        betweenness_cent = nx.betweenness_centrality(self.graph)
        
        try:
            pagerank = nx.pagerank(self.graph)
        except:
            pagerank = {node: 0 for node in self.graph.nodes}
        
        metrics = {}
        for node in self.graph.nodes:
            metrics[node] = {
                "degree_centrality": degree_cent.get(node, 0),
                "betweenness_centrality": betweenness_cent.get(node, 0),
                "pagerank": pagerank.get(node, 0),
                "in_degree": self.graph.in_degree(node),
                "out_degree": self.graph.out_degree(node),
                "is_suspicious": node in self.suspicious_nodes
            }
        
        return metrics

    def detect_communities(self) -> Dict[str, int]:
        """Detect network communities using Louvain algorithm."""
        if len(self.graph.nodes) == 0:
            return {}
        
        # Convert to undirected for community detection
        undirected = self.graph.to_undirected()
        
        try:
            partition = community_louvain.best_partition(undirected)
            return partition
        except:
            return {node: 0 for node in self.graph.nodes}

    def get_top_talkers(self, limit: int = 10) -> List[Dict]:
        """Get nodes with highest traffic volume."""
        node_traffic = defaultdict(int)
        
        for src, dst in self.flow_count:
            node_traffic[src] += self.flow_count[(src, dst)]
            node_traffic[dst] += self.flow_count[(src, dst)]
        
        sorted_nodes = sorted(node_traffic.items(), key=lambda x: x[1], reverse=True)
        
        return [
            {"ip": node, "flow_count": count, "is_suspicious": node in self.suspicious_nodes}
            for node, count in sorted_nodes[:limit]
        ]

    def get_graph_data(self) -> Dict:
        """Export graph data for visualization."""
        nodes = []
        edges = []
        
        centrality = self.get_centrality_metrics()
        communities = self.detect_communities()
        
        for node in self.graph.nodes:
            nodes.append({
                "id": node,
                "label": node,
                "suspicious": node in self.suspicious_nodes,
                "community": communities.get(node, 0),
                "degree_centrality": centrality.get(node, {}).get("degree_centrality", 0),
                "in_degree": centrality.get(node, {}).get("in_degree", 0),
                "out_degree": centrality.get(node, {}).get("out_degree", 0),
            })
        
        for src, dst, data in self.graph.edges(data=True):
            edges.append({
                "source": src,
                "target": dst,
                "weight": data["weight"],
                "flow_count": len(data["flows"]),
            })
        
        return {
            "nodes": nodes,
            "edges": edges,
            "stats": {
                "total_nodes": len(nodes),
                "total_edges": len(edges),
                "suspicious_nodes": len(self.suspicious_nodes),
                "communities": len(set(communities.values())),
            }
        }
