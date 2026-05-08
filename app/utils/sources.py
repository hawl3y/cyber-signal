SOURCE_REGISTRY = [
    {
        "name": "the-record-cybercrime",
        "source_class": "incident_news",
        "signal_kind": "incident",
        "ingest_type": "rss",
        "url": "https://therecord.media/news/cybercrime/feed",
        "active": True,
        "tier": "core",
    },
    {
        "name": "bleepingcomputer",
        "source_class": "incident_news",
        "signal_kind": "incident",
        "ingest_type": "rss",
        "url": "https://www.bleepingcomputer.com/feed/",
        "active": True,
        "tier": "core",
    },
    {
        "name": "krebsonsecurity",
        "source_class": "incident_news",
        "signal_kind": "incident",
        "ingest_type": "rss",
        "url": "https://krebsonsecurity.com/feed/",
        "active": True,
        "tier": "curated",
        "tier_trusted_alone": True,
    },
    {
        "name": "cisa-alerts-advisories",
        "source_class": "official_alert",
        "signal_kind": "activity",
        "ingest_type": "rss",
        "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        "active": True,
        "tier": "curated",
    },
    {
        "name": "cisa-kev",
        "source_class": "exploited_vulnerability",
        "signal_kind": "activity",
        "ingest_type": "json",
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "active": True,
        "tier": "curated",
    },
    {
        "name": "sec-edgar-cyber-8k",
        "source_class": "primary_disclosure",
        "signal_kind": "incident",
        "ingest_type": "sec_edgar_cyber",
        "url": "https://efts.sec.gov/LATEST/search-index?q=%22material+cybersecurity+incident%22&forms=8-K",
        "active": True,
        "tier": "official",
        "tier_trusted_alone": True,
    },
]


def load_active_sources():
    """
    Return only active sources for ingestion.
    """
    return [source for source in SOURCE_REGISTRY if source.get("active")]


def get_source_config(source_name):
    """
    Lookup source metadata by name.
    """
    for source in SOURCE_REGISTRY:
        if source.get("name") == source_name:
            return source
    return None