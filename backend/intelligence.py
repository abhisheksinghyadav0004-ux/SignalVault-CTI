from ipaddress import ip_address
from urllib.parse import urlsplit

from sqlalchemy.orm import Session

from backend.models import Indicator

SOURCE_WEIGHTS = {
    "cisa-kev": 35,
    "threatfox": 35,
    "ransomware.live": 30,
    "nvd": 20,
    "manual": 10,
}

MITRE_CONTEXT = {
    "phishing": {"id": "T1566", "name": "Phishing"},
    "credential-theft": {"id": "T1555", "name": "Credentials from Password Stores"},
    "command-and-control": {"id": "T1071", "name": "Application Layer Protocol"},
    "malware": {"id": "T1204", "name": "User Execution"},
    "ransomware": {"id": "T1486", "name": "Data Encrypted for Impact"},
}

MITRE_CONTEXT_BY_ID = {
    technique["id"]: technique
    for technique in MITRE_CONTEXT.values()
}


def infer_indicator_type(value):
    clean_value = value.strip()

    try:
        ip_address(clean_value)
        return "ip"
    except ValueError:
        pass

    if clean_value.lower().startswith(("http://", "https://")):
        return "url"

    if clean_value.upper().startswith("CVE-"):
        return "cve"

    if len(clean_value) in {32, 40, 64} and all(
        character in "0123456789abcdefABCDEF"
        for character in clean_value
    ):
        return "hash"

    return "domain"


def normalize_indicator(value, indicator_type=None):
    clean_value = value.strip()

    if not clean_value:
        raise ValueError("Indicator value cannot be empty.")

    resolved_type = indicator_type or infer_indicator_type(clean_value)

    if resolved_type == "ip":
        return str(ip_address(clean_value))

    if resolved_type == "url":
        parsed_url = urlsplit(clean_value)
        return (
            f"{parsed_url.scheme.lower()}://"
            f"{parsed_url.netloc.lower()}"
            f"{parsed_url.path.rstrip('/')}"
        )

    if resolved_type == "cve":
        return clean_value.upper()

    return clean_value.lower().rstrip(".")


def risk_level_from_score(score):
    if score >= 70:
        return "High"

    if score >= 35:
        return "Medium"

    return "Low"


def parse_csv_text(value):
    return {
        item.strip().lower()
        for item in value.split(",")
        if item.strip()
    }


def calculate_risk(sources, sightings):
    source_score = sum(
        SOURCE_WEIGHTS.get(source, SOURCE_WEIGHTS["manual"])
        for source in sources
    )

    recurrence_score = min(max(sightings - 1, 0) * 12, 30)
    return min(source_score + recurrence_score, 100)


def serialize_indicator(indicator):
    tags = sorted(parse_csv_text(indicator.tags))
    mitre = [
        MITRE_CONTEXT[tag]
        for tag in tags
        if tag in MITRE_CONTEXT
    ]

    return {
        "id": indicator.id,
        "type": indicator.indicator_type,
        "value": indicator.value,
        "normalizedValue": indicator.normalized_value,
        "riskScore": indicator.risk_score,
        "riskLevel": indicator.risk_level,
        "sources": sorted(parse_csv_text(indicator.feed_sources)),
        "tags": tags,
        "mitreTechniques": mitre,
        "analystNote": indicator.analyst_note,
        "confidence": indicator.confidence,
        "disposition": indicator.disposition,
        "firstSeen": indicator.first_seen.isoformat(),
        "lastSeen": indicator.last_seen.isoformat(),
        "sightings": indicator.sighting_count,
    }


def upsert_indicator(
    database_session: Session,
    value,
    source,
    tags=None,
    indicator_type=None,
):
    normalized_value = normalize_indicator(value, indicator_type)
    resolved_type = indicator_type or infer_indicator_type(value)

    indicator = (
        database_session.query(Indicator)
        .filter(Indicator.normalized_value == normalized_value)
        .one_or_none()
    )

    incoming_source = source.strip().lower() or "manual"
    incoming_tags = {
        tag.strip().lower()
        for tag in (tags or [])
        if tag.strip()
    }

    if indicator is None:
        sources = {incoming_source}
        risk_score = calculate_risk(sources, sightings=1)

        indicator = Indicator(
            indicator_type=resolved_type,
            value=value.strip(),
            normalized_value=normalized_value,
            risk_score=risk_score,
            risk_level=risk_level_from_score(risk_score),
            feed_sources=", ".join(sorted(sources)),
            tags=", ".join(sorted(incoming_tags)),
            sighting_count=1,
        )
        database_session.add(indicator)
    else:
        sources = parse_csv_text(indicator.feed_sources)
        sources.add(incoming_source)

        stored_tags = parse_csv_text(indicator.tags)
        stored_tags.update(incoming_tags)

        indicator.sighting_count += 1
        indicator.feed_sources = ", ".join(sorted(sources))
        indicator.tags = ", ".join(sorted(stored_tags))
        indicator.risk_score = calculate_risk(
            sources,
            indicator.sighting_count,
        )
        indicator.risk_level = risk_level_from_score(indicator.risk_score)

    database_session.commit()
    database_session.refresh(indicator)

    return serialize_indicator(indicator)
