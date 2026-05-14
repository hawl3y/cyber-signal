SOURCE_REGISTRY = [
    {
        "name": "the-record-cybercrime",
        "display_label": "The Record",
        "source_class": "incident_news",
        "signal_kind": "incident",
        "ingest_type": "rss",
        "url": "https://therecord.media/news/cybercrime/feed",
        "active": True,
        "tier": "core",
    },
    {
        "name": "bleepingcomputer",
        "display_label": "BleepingComputer",
        "source_class": "incident_news",
        "signal_kind": "incident",
        "ingest_type": "rss",
        "url": "https://www.bleepingcomputer.com/feed/",
        "active": True,
        "tier": "core",
    },
    {
        "name": "krebsonsecurity",
        "display_label": "Krebs on Security",
        "source_class": "incident_news",
        "signal_kind": "incident",
        "ingest_type": "rss",
        "url": "https://krebsonsecurity.com/feed/",
        "active": True,
        "tier": "curated",
        "tier_trusted_alone": True,
    },
    {
        "name": "the-hacker-news",
        "display_label": "The Hacker News",
        "source_class": "incident_news",
        "signal_kind": "incident",
        "ingest_type": "rss",
        "url": "https://feeds.feedburner.com/TheHackersNews",
        "active": True,
        "tier": "core",
    },
    {
        "name": "ncsc-uk",
        "display_label": "NCSC",
        "source_class": "official_alert",
        "signal_kind": "incident",
        "ingest_type": "rss",
        "url": "https://www.ncsc.gov.uk/api/1/services/v1/news-rss-feed.xml",
        "active": True,
        "tier": "curated",
        "tier_trusted_alone": True,
    },
    {
        "name": "cisa-alerts-advisories",
        "display_label": "CISA Advisories",
        "source_class": "official_alert",
        "signal_kind": "activity",
        "ingest_type": "rss",
        "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        "active": True,
        "tier": "curated",
    },
    {
        "name": "cisa-kev",
        "display_label": "CISA KEV",
        "source_class": "exploited_vulnerability",
        "signal_kind": "activity",
        "ingest_type": "json",
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "active": True,
        "tier": "curated",
    },
    {
        "name": "ransomware-live",
        "display_label": "ransomware.live",
        "source_class": "incident_news",
        "signal_kind": "incident",
        "ingest_type": "ransomware_live",
        "url": "https://api.ransomware.live/recentvictims",
        "active": True,
        "tier": "curated",
        "tier_trusted_alone": True,
    },
    {
        "name": "sec-edgar-cyber-8k",
        "display_label": "SEC EDGAR",
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