from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models.investigation import DomainInformation, Investigation
from app.services.correlation_service import build_threat_correlation_graph


def test_correlates_domains_using_shared_nameservers():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine)()
    try:
        for domain in ("alpha.test", "beta.test"):
            investigation = Investigation(
                target_url=f"https://{domain}",
                normalized_url=f"https://{domain}/",
                hostname=domain,
                domain=domain,
                overall_risk="SUSPICIOUS",
                risk_score=40,
                confidence="MEDIUM",
                summary="Test investigation",
                status="COMPLETED",
            )
            session.add(investigation)
            session.flush()
            session.add(DomainInformation(
                investigation_id=investigation.id,
                domain=domain,
                nameservers=["ns1.shared.test"],
            ))
        session.commit()

        graph = build_threat_correlation_graph(session)
        assert any(edge["relationship"] == "SHARED_NAMESERVER" for edge in graph["edges"])
        assert graph["summary"]["shared_nameserver_relationships"] == 1
    finally:
        session.close()
        engine.dispose()
