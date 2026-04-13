import re
from collections import Counter
from datetime import datetime, UTC

from app.extensions import db
from app.models import CyberEvent, EventSourceLink, RawArticle, ArticleExtraction


def get_linked_articles(event_id):
    """
    Retrieve articles linked to an event.
    """
    links = EventSourceLink.query.filter_by(cyber_event_id=event_id).all()
    return [RawArticle.query.get(link.raw_article_id) for link in links]


def get_extractions(event_id):
    """
    Retrieve extractions for an event.
    """
    links = EventSourceLink.query.filter_by(cyber_event_id=event_id).all()
    article_ids = [link.raw_article_id for link in links]

    if not article_ids:
        return []

    return ArticleExtraction.query.filter(
        ArticleExtraction.raw_article_id.in_(article_ids)
    ).all()


def _most_common_non_empty(values):
    cleaned = []
    for value in values:
        if value is None:
            continue
        if isinstance(value, str):
            value = value.strip()
            if not value:
                continue
        cleaned.append(value)

    if not cleaned:
        return None

    return Counter(cleaned).most_common(1)[0][0]

def _infer_geography_from_articles(linked_articles):
    """
    Lightweight fallback geography inference from article text when
    extraction does not populate country/region.
    """
    text = " ".join(
        [
            (article.title or "").strip()
            + " "
            + (article.summary or "").strip()
            + " "
            + (article.content or "").strip()
            for article in linked_articles
            if article
        ]
    ).lower()

    geography_map = [
        (["netherlands", "dutch"], "Netherlands", "Europe"),
        (
            [
                "united states",
                "u.s.",
                "american",
                "securities exchange commission",
                "sec ",
                "(sec)",
            ],
            "United States",
            "North America",
        ),
        (["canada"], "Canada", "North America"),
        (["mexico"], "Mexico", "North America"),
        (["united kingdom", "britain", "british", "england"], "United Kingdom", "Europe"),
        (["germany", "german"], "Germany", "Europe"),
        (["france", "french"], "France", "Europe"),
        (["italy", "italian"], "Italy", "Europe"),
        (["spain", "spanish"], "Spain", "Europe"),
        (["portugal", "portuguese"], "Portugal", "Europe"),
        (["belgium", "belgian"], "Belgium", "Europe"),
        (["sweden", "swedish"], "Sweden", "Europe"),
        (["norway", "norwegian"], "Norway", "Europe"),
        (["denmark", "danish"], "Denmark", "Europe"),
        (["finland", "finnish"], "Finland", "Europe"),
        (["poland", "polish"], "Poland", "Europe"),
        (["ukraine"], "Ukraine", "Europe"),
        (["russia", "russian"], "Russia", "Europe"),
        (["turkey", "turkish"], "Turkey", "Europe"),
        (["china", "chinese"], "China", "Asia"),
        (["taiwan"], "Taiwan", "Asia"),
        (["japan", "japanese"], "Japan", "Asia"),
        (["india", "indian"], "India", "Asia"),
        (["singapore"], "Singapore", "Asia"),
        (["south korea", "korea", "korean"], "South Korea", "Asia"),
        (["hong kong"], "Hong Kong", "Asia"),
        (["israel"], "Israel", "Middle East"),
        (["saudi arabia", "saudi"], "Saudi Arabia", "Middle East"),
        (["united arab emirates", "uae"], "United Arab Emirates", "Middle East"),
        (["australia", "australian"], "Australia", "Oceania"),
        (["new zealand"], "New Zealand", "Oceania"),
        (["brazil", "brazilian"], "Brazil", "South America"),
        (["argentina"], "Argentina", "South America"),
        (["chile"], "Chile", "South America"),
        (["colombia"], "Colombia", "South America"),
        (["south africa"], "South Africa", "Africa"),
        (["nigeria"], "Nigeria", "Africa"),
        (["kenya"], "Kenya", "Africa"),
        (["egypt"], "Egypt", "Africa"),
    ]

    for keywords, country, region in geography_map:
        if any(keyword in text for keyword in keywords):
            return {"country": country, "region": region, "city": None}

    return {"country": None, "region": None, "city": None}

def _infer_org_geography_from_articles(linked_articles, victim_org_name):
    """
    Infer organization home geography dynamically from article text when
    explicit incident geography is missing.

    This is a fallback only. It looks for patterns such as:
    - U.S.-based Rockstar Games
    - France-based CPUID
    - Rockstar Games, a U.S. company
    - CPUID, a French company

    It does not hard-code organization names.
    """
    if not linked_articles or not victim_org_name:
        return {"country": None, "region": None, "city": None}

    org = re.escape(victim_org_name.strip())
    if not org:
        return {"country": None, "region": None, "city": None}

    text = " ".join(
        [
            (article.title or "").strip()
            + " "
            + (article.summary or "").strip()
            + " "
            + (article.content or "").strip()
            for article in linked_articles
            if article
        ]
    )

    country_patterns = [
        (
            [
                rf"\b(?:u\.s\.|u\.s\.a\.|united states|american)-based\s+{org}\b",
                rf"\b{org},?\s+(?:an?|the)\s+(?:u\.s\.|u\.s\.a\.|united states|american)\s+(?:company|firm|developer|vendor|provider|maker)\b",
                rf"\b{org}\s+is\s+(?:based|headquartered)\s+in\s+(?:the\s+)?(?:u\.s\.|u\.s\.a\.|united states)\b",
            ],
            "United States",
            "North America",
        ),
        (
            [
                rf"\bcanadian-based\s+{org}\b",
                rf"\b{org},?\s+(?:an?|the)\s+canadian\s+(?:company|firm|developer|vendor|provider|maker)\b",
                rf"\b{org}\s+is\s+(?:based|headquartered)\s+in\s+canada\b",
            ],
            "Canada",
            "North America",
        ),
        (
            [
                rf"\bdutch\s+{org}\b",
                rf"\bnetherlands-based\s+{org}\b",
                rf"\b{org},?\s+(?:a|the)\s+dutch\s+(?:company|firm|developer|vendor|provider|maker|chain)\b",
                rf"\b{org}\s+is\s+(?:based|headquartered)\s+in\s+the\s+netherlands\b",
            ],
            "Netherlands",
            "Europe",
        ),
        (
            [
                rf"\bfrench\s+{org}\b",
                rf"\bfrance-based\s+{org}\b",
                rf"\b{org},?\s+(?:a|the)\s+french\s+(?:company|firm|developer|vendor|provider|maker)\b",
                rf"\b{org}\s+is\s+(?:based|headquartered)\s+in\s+france\b",
            ],
            "France",
            "Europe",
        ),
        (
            [
                rf"\bgerman\s+{org}\b",
                rf"\bgermany-based\s+{org}\b",
                rf"\b{org},?\s+(?:a|the)\s+german\s+(?:company|firm|developer|vendor|provider|maker)\b",
                rf"\b{org}\s+is\s+(?:based|headquartered)\s+in\s+germany\b",
            ],
            "Germany",
            "Europe",
        ),
        (
            [
                rf"\bbritish\s+{org}\b",
                rf"\buk-based\s+{org}\b",
                rf"\bunited kingdom-based\s+{org}\b",
                rf"\b{org},?\s+(?:a|the)\s+british\s+(?:company|firm|developer|vendor|provider|maker)\b",
                rf"\b{org}\s+is\s+(?:based|headquartered)\s+in\s+(?:the\s+)?united kingdom\b",
            ],
            "United Kingdom",
            "Europe",
        ),
    ]

    for patterns, country, region in country_patterns:
        for pattern in patterns:
            if re.search(pattern, text, flags=re.IGNORECASE):
                return {"country": country, "region": region, "city": None}

    return {"country": None, "region": None, "city": None}

def _coordinates_for_location(city=None, country=None, region=None):
    """
    Deterministic fallback coordinates for map display.
    Favor region over country for broader visual grouping.
    """
    if city == "New York" and country == "United States":
        return 40.7128, -74.0060

    region_coordinates = {
        "North America": (54.5260, -105.2551),
        "South America": (-8.7832, -55.4915),
        "Europe": (54.5260, 15.2551),
        "Asia": (34.0479, 100.6197),
        "Middle East": (29.2985, 42.5510),
        "Africa": (1.6508, 17.6791),
        "Oceania": (-22.7359, 140.0188),
    }

    country_coordinates = {
        "United States": (39.8283, -98.5795),
        "Canada": (56.1304, -106.3468),
        "Mexico": (23.6345, -102.5528),
        "Netherlands": (52.1326, 5.2913),
        "United Kingdom": (55.3781, -3.4360),
        "Germany": (51.1657, 10.4515),
        "France": (46.2276, 2.2137),
        "Italy": (41.8719, 12.5674),
        "Spain": (40.4637, -3.7492),
        "Portugal": (39.3999, -8.2245),
        "Belgium": (50.5039, 4.4699),
        "Sweden": (60.1282, 18.6435),
        "Norway": (60.4720, 8.4689),
        "Denmark": (56.2639, 9.5018),
        "Finland": (61.9241, 25.7482),
        "Poland": (51.9194, 19.1451),
        "Ukraine": (48.3794, 31.1656),
        "Russia": (61.5240, 105.3188),
        "Turkey": (38.9637, 35.2433),
        "China": (35.8617, 104.1954),
        "Taiwan": (23.6978, 120.9605),
        "Japan": (36.2048, 138.2529),
        "India": (20.5937, 78.9629),
        "Singapore": (1.3521, 103.8198),
        "South Korea": (35.9078, 127.7669),
        "Hong Kong": (22.3193, 114.1694),
        "Israel": (31.0461, 34.8516),
        "Saudi Arabia": (23.8859, 45.0792),
        "United Arab Emirates": (23.4241, 53.8478),
        "Australia": (-25.2744, 133.7751),
        "New Zealand": (-40.9006, 174.8860),
        "Brazil": (-14.2350, -51.9253),
        "Argentina": (-38.4161, -63.6167),
        "Chile": (-35.6751, -71.5430),
        "Colombia": (4.5709, -74.2973),
        "South Africa": (-30.5595, 22.9375),
        "Nigeria": (9.0820, 8.6753),
        "Kenya": (-0.0236, 37.9062),
        "Egypt": (26.8206, 30.8025),
    }

    if region in region_coordinates:
        return region_coordinates[region]

    if country in country_coordinates:
        return country_coordinates[country]

    return None, None


def aggregate_event_data(linked_articles, extractions, source_count):
    """
    Aggregate structured event data from linked articles and extractions.
    """
    if not linked_articles:
        return {}

    primary_article = linked_articles[0]

    victim_org_name = _most_common_non_empty(
        [extraction.victim_org_name for extraction in extractions]
    )
    victim_org_normalized = _most_common_non_empty(
        [extraction.victim_org_normalized for extraction in extractions]
    )
    industry = _most_common_non_empty(
        [extraction.industry for extraction in extractions]
    )
    attack_type = _most_common_non_empty(
        [extraction.attack_type for extraction in extractions]
    )
    access_vector = _most_common_non_empty(
        [extraction.access_vector for extraction in extractions]
    )
    impact_type = _most_common_non_empty(
        [extraction.impact_type for extraction in extractions]
    )
    actor_name = _most_common_non_empty(
        [extraction.actor_name for extraction in extractions]
    )
    actor_type = _most_common_non_empty(
        [extraction.actor_type for extraction in extractions]
    )
    attribution_status = _most_common_non_empty(
        [extraction.attribution_status for extraction in extractions]
    )
    vuln_status = _most_common_non_empty(
        [extraction.vuln_status for extraction in extractions]
    )
    zero_day_flag = _most_common_non_empty(
        [extraction.zero_day_flag for extraction in extractions]
    )
    region = _most_common_non_empty(
        [extraction.region for extraction in extractions]
    )
    country = _most_common_non_empty(
        [extraction.country for extraction in extractions]
    )
    city = _most_common_non_empty(
        [extraction.city for extraction in extractions]
    )
    summary_short = _most_common_non_empty(
        [extraction.short_event_summary for extraction in extractions]
    )

    if not country and not region and not city:
        fallback_geo = _infer_geography_from_articles(linked_articles)
        country = fallback_geo["country"]
        region = fallback_geo["region"]
        city = fallback_geo["city"]

    if not country and not region and not city and victim_org_name:
        org_fallback_geo = _infer_org_geography_from_articles(
            linked_articles,
            victim_org_name,
        )
        country = org_fallback_geo["country"]
        region = org_fallback_geo["region"]
        city = org_fallback_geo["city"]

    if city:
        geography_type = "city"
    elif country:
        geography_type = "country"
    elif region:
        geography_type = "region"
    else:
        geography_type = None

    latitude, longitude = _coordinates_for_location(
        city=city,
        country=country,
        region=region,
    )

    return {
        "canonical_title": primary_article.title,
        "victim_org_name": victim_org_name,
        "victim_org_normalized": victim_org_normalized,
        "industry": industry,
        "attack_type": attack_type,
        "access_vector": access_vector,
        "impact_type": impact_type,
        "actor_name": actor_name,
        "actor_type": actor_type,
        "attribution_status": attribution_status,
        "vuln_status": vuln_status,
        "zero_day_flag": zero_day_flag,
        "region": region,
        "country": country,
        "city": city,
        "geography_type": geography_type,
        "latitude": latitude,
        "longitude": longitude,
        "summary_short": summary_short,
        "source_count": source_count,
        "last_enriched_at": datetime.now(UTC),
    }


def update_event(event_id, event_data):
    """
    Update event record.
    """
    event = CyberEvent.query.get(event_id)

    if not event or not event_data:
        return event

    event.canonical_title = event_data.get("canonical_title", event.canonical_title)
    event.victim_org_name = event_data.get("victim_org_name", event.victim_org_name)
    event.victim_org_normalized = event_data.get(
        "victim_org_normalized",
        event.victim_org_normalized,
    )
    event.industry = event_data.get("industry", event.industry)
    event.attack_type = event_data.get("attack_type", event.attack_type)
    event.access_vector = event_data.get("access_vector", event.access_vector)
    event.impact_type = event_data.get("impact_type", event.impact_type)
    event.actor_name = event_data.get("actor_name", event.actor_name)
    event.actor_type = event_data.get("actor_type", event.actor_type)
    event.attribution_status = event_data.get(
        "attribution_status",
        event.attribution_status,
    )
    event.vuln_status = event_data.get("vuln_status", event.vuln_status)
    event.zero_day_flag = event_data.get("zero_day_flag", event.zero_day_flag)
    event.region = event_data.get("region", event.region)
    event.country = event_data.get("country", event.country)
    event.city = event_data.get("city", event.city)
    event.geography_type = event_data.get("geography_type", event.geography_type)
    event.latitude = event_data.get("latitude", event.latitude)
    event.longitude = event_data.get("longitude", event.longitude)
    event.summary_short = event_data.get("summary_short", event.summary_short)
    event.source_count = event_data.get("source_count", event.source_count)
    event.last_enriched_at = event_data.get(
        "last_enriched_at",
        event.last_enriched_at,
    )

    db.session.commit()
    return event