from typing import Dict, Any, List, Set
from sqlalchemy.orm import Session
from app.models.investigation import Investigation, DomainInformation
from app.models.threat_report import ThreatReport, ThreatRelationship

def build_threat_correlation_graph(db: Session) -> Dict[str, Any]:
    """
    Computes deterministic correlation clusters across investigations, community threat reports,
    shared IP infrastructure, nameservers, and brand typosquatting targets.
    
    Returns nodes and edges formatted for visualization.
    """
    investigations = db.query(Investigation).order_by(Investigation.created_at.desc()).limit(50).all()
    reports = db.query(ThreatReport).order_by(ThreatReport.created_at.desc()).limit(50).all()

    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    
    seen_nodes: Set[str] = set()

    def add_node(node_id: str, label: str, node_type: str, risk: str = "INFO", details: Dict[str, Any] = None):
        if node_id not in seen_nodes:
            seen_nodes.add(node_id)
            nodes.append({
                "id": node_id,
                "label": label,
                "type": node_type, # DOMAIN, IP, NAMESERVER, REPORT, BRAND
                "risk": risk,
                "details": details or {}
            })

    def add_edge(source: str, target: str, relationship: str, evidence: str):
        edge_id = f"{source}->{target}:{relationship}"
        edges.append({
            "id": edge_id,
            "source": source,
            "target": target,
            "relationship": relationship,
            "evidence": evidence
        })

    # Index IPs and Nameservers
    ip_to_domains: Dict[str, List[str]] = {}
    ns_to_domains: Dict[str, List[str]] = {}

    for inv in investigations:
        domain_node_id = f"domain:{inv.domain}"
        add_node(
            domain_node_id,
            inv.domain,
            "DOMAIN",
            risk=inv.overall_risk,
            details={"investigation_id": inv.id, "target_url": inv.target_url, "risk_score": inv.risk_score}
        )

        if inv.ip_address and inv.ip_address != "Not available":
            ip_node_id = f"ip:{inv.ip_address}"
            add_node(ip_node_id, inv.ip_address, "IP", risk="INFO")
            add_edge(domain_node_id, ip_node_id, "RESOLVES_TO", f"DNS A-record for {inv.domain}")
            ip_to_domains.setdefault(inv.ip_address, []).append(domain_node_id)

        if inv.domain_info:
            for ns in (inv.domain_info.nameservers or []):
                ns_clean = str(ns).lower()
                ns_node_id = f"ns:{ns_clean}"
                add_node(ns_node_id, ns_clean, "NAMESERVER", risk="INFO")
                add_edge(domain_node_id, ns_node_id, "DELEGATED_TO", f"Authoritative NS for {inv.domain}")
                ns_to_domains.setdefault(ns_clean, []).append(domain_node_id)

    # Link Threat Reports
    for r in reports:
        report_node_id = f"report:{r.id}"
        add_node(
            report_node_id,
            f"Report: {r.report_type} ({r.domain[:18]})",
            "REPORT",
            risk=r.severity,
            details={"report_id": r.id, "domain": r.domain, "status": r.verification_status}
        )
        domain_node_id = f"domain:{r.domain}"
        if domain_node_id in seen_nodes:
            add_edge(report_node_id, domain_node_id, "TARGETS_DOMAIN", f"Community report filed against {r.domain}")
        else:
            add_node(domain_node_id, r.domain, "DOMAIN", risk=r.severity)
            add_edge(report_node_id, domain_node_id, "TARGETS_DOMAIN", f"Community report filed against {r.domain}")

    # Discover and flag Co-hosting / Shared Infrastructure relationships
    correlations_found = 0
    for ip, domain_ids in ip_to_domains.items():
        if len(domain_ids) > 1:
            for i in range(len(domain_ids)):
                for j in range(i + 1, len(domain_ids)):
                    add_edge(
                        domain_ids[i],
                        domain_ids[j],
                        "SHARED_HOSTING_IP",
                        f"Both domains resolve to shared IP address {ip}"
                    )
                    correlations_found += 1

    return {
        "nodes": nodes,
        "edges": edges,
        "summary": {
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "shared_infrastructure_clusters": correlations_found
        }
    }
