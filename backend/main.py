from collections import Counter
from datetime import datetime, timezone

import httpx

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from backend.database import get_database_session, initialize_database
from backend.intelligence import MITRE_CONTEXT, MITRE_CONTEXT_BY_ID, serialize_indicator, upsert_indicator
from backend.models import FeedSync, Indicator

app = FastAPI(
    title="SignalVault CTI API",
    description="Threat intelligence ingestion, scoring, and investigation API.",
    version="0.2.0",
)

CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class IndicatorInput(BaseModel):
    value: str = Field(min_length=1, max_length=500)
    source: str = Field(default="manual", max_length=100)
    indicator_type: str | None = Field(default=None, max_length=32)
    tags: list[str] = Field(default_factory=list)


class InvestigationUpdate(BaseModel):
    analyst_note: str = Field(default="", max_length=4000)
    confidence: str = Field(default="Unassessed", pattern="^(Unassessed|Low|Medium|High)$")
    disposition: str = Field(default="Open", pattern="^(Open|Monitoring|Escalated|Closed)$")


class FeedSyncInput(BaseModel):
    limit: int = Field(default=25, ge=1, le=100)


@app.on_event("startup")
def startup():
    initialize_database()


@app.get("/")
def root():
    return {
        "service": "SignalVault CTI API",
        "status": "online",
        "docs": "/docs",
    }


@app.get("/api/health")
def health():
    return {
        "status": "healthy",
        "service": "SignalVault CTI",
        "database": "connected",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/api/indicators")
def create_indicator(
    indicator_input: IndicatorInput,
    database_session: Session = Depends(get_database_session),
):
    indicator = upsert_indicator(
        database_session=database_session,
        value=indicator_input.value,
        source=indicator_input.source,
        tags=indicator_input.tags,
        indicator_type=indicator_input.indicator_type,
    )

    return {
        "message": "Indicator processed successfully.",
        "indicator": indicator,
    }


@app.get("/api/indicators")
def list_indicators(
    search: str | None = None,
    risk_level: str | None = None,
    indicator_type: str | None = None,
    limit: int = Query(default=100, ge=1, le=250),
    database_session: Session = Depends(get_database_session),
):
    statement = select(Indicator).order_by(Indicator.last_seen.desc())

    if search:
        search_pattern = f"%{search.strip()}%"
        statement = statement.where(
            or_(
                Indicator.value.ilike(search_pattern),
                Indicator.tags.ilike(search_pattern),
                Indicator.feed_sources.ilike(search_pattern),
            )
        )

    if risk_level:
        statement = statement.where(
            Indicator.risk_level == risk_level.title()
        )

    if indicator_type:
        statement = statement.where(
            Indicator.indicator_type == indicator_type.lower()
        )

    indicators = database_session.scalars(statement.limit(limit)).all()

    return {
        "total": len(indicators),
        "items": [
            serialize_indicator(indicator)
            for indicator in indicators
        ],
    }


@app.get("/api/dashboard")
def dashboard(
    database_session: Session = Depends(get_database_session),
):
    indicators = database_session.scalars(select(Indicator)).all()

    risk_distribution = Counter(
        indicator.risk_level
        for indicator in indicators
    )
    source_distribution = Counter()
    mitre_distribution = Counter()

    for indicator in indicators:
        source_distribution.update(
            source
            for source in indicator.feed_sources.split(",")
            if source.strip()
        )
        for tag in indicator.tags.split(","):
            technique = MITRE_CONTEXT.get(tag.strip().lower())
            if technique:
                mitre_distribution[technique["id"]] += 1

    feed_syncs = database_session.scalars(select(FeedSync)).all()

    return {
        "summary": {
            "totalIndicators": len(indicators),
            "highRisk": risk_distribution["High"],
            "mediumRisk": risk_distribution["Medium"],
            "lowRisk": risk_distribution["Low"],
        },
        "riskDistribution": dict(risk_distribution),
        "sourceDistribution": dict(source_distribution),
        "mitreCoverage": [
            {
                "id": technique_id,
                "name": MITRE_CONTEXT_BY_ID[technique_id]["name"],
                "count": count,
            }
            for technique_id, count in mitre_distribution.most_common()
        ],
        "feeds": [serialize_feed_sync(feed_sync) for feed_sync in feed_syncs],
        "recentIndicators": [
            serialize_indicator(indicator)
            for indicator in sorted(
                indicators,
                key=lambda item: item.last_seen,
                reverse=True,
            )[:8]
        ],
    }


def serialize_feed_sync(feed_sync: FeedSync):
    return {
        "source": feed_sync.source,
        "lastSuccess": feed_sync.last_success.isoformat() if feed_sync.last_success else None,
        "lastError": feed_sync.last_error or None,
        "recordsProcessed": feed_sync.records_processed,
    }


def update_feed_sync(
    database_session: Session,
    source: str,
    records_processed: int = 0,
    error: str = "",
):
    feed_sync = database_session.scalar(
        select(FeedSync).where(FeedSync.source == source)
    )
    if feed_sync is None:
        feed_sync = FeedSync(source=source)
        database_session.add(feed_sync)

    if error:
        feed_sync.last_error = error
    else:
        feed_sync.last_success = datetime.now(timezone.utc)
        feed_sync.last_error = ""
        feed_sync.records_processed = records_processed

    database_session.commit()
    database_session.refresh(feed_sync)
    return feed_sync


@app.post("/api/feeds/cisa-kev/sync")
def sync_cisa_kev(
    request: FeedSyncInput,
    database_session: Session = Depends(get_database_session),
):
    """Import a bounded sample of the official CISA KEV catalog."""
    try:
        response = httpx.get(
            CISA_KEV_URL,
            headers={"User-Agent": "SignalVault-CTI/0.2 (academic project)"},
            timeout=20.0,
            follow_redirects=True,
        )
        response.raise_for_status()
        vulnerabilities = response.json().get("vulnerabilities", [])
    except (httpx.HTTPError, ValueError) as error:
        update_feed_sync(
            database_session,
            source="cisa-kev",
            error="CISA KEV feed is unavailable. Try again later.",
        )
        raise HTTPException(
            status_code=502,
            detail="CISA KEV feed is unavailable. Try again later.",
        ) from error

    processed = []
    for vulnerability in vulnerabilities[: request.limit]:
        tags = [
            "kev",
            vulnerability.get("vendorProject", "unknown-vendor").lower(),
            vulnerability.get("product", "unknown-product").lower(),
        ]
        processed.append(
            upsert_indicator(
                database_session=database_session,
                value=vulnerability["cveID"],
                source="cisa-kev",
                tags=tags,
                indicator_type="cve",
            )
        )

    feed_sync = update_feed_sync(
        database_session,
        source="cisa-kev",
        records_processed=len(processed),
    )
    return {
        "message": f"Imported {len(processed)} CISA KEV records.",
        "processed": len(processed),
        "feed": serialize_feed_sync(feed_sync),
    }


@app.patch("/api/indicators/{indicator_id}/investigation")
def update_investigation(
    indicator_id: int,
    update: InvestigationUpdate,
    database_session: Session = Depends(get_database_session),
):
    indicator = database_session.get(Indicator, indicator_id)
    if indicator is None:
        raise HTTPException(status_code=404, detail="Indicator not found.")

    indicator.analyst_note = update.analyst_note.strip()
    indicator.confidence = update.confidence
    indicator.disposition = update.disposition
    database_session.commit()
    database_session.refresh(indicator)

    return {"message": "Investigation context saved.", "indicator": serialize_indicator(indicator)}
