def load_active_sources():
    """
    Return only active high-signal sources for Cyber Signal ingestion.

    Keep this curated and operationally controlled so new source types can be
    staged safely without entering the live pipeline until explicitly enabled.
    """
    sources = [
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
        },
        {
            "name": "cisa-alerts-advisories",
            "source_class": "official_alert",
            "signal_kind": "near_incident",
            "ingest_type": "rss",
            "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
            "active": False,
            "tier": "curated",
        },
        {
            "name": "cisa-kev",
            "source_class": "exploited_vulnerability",
            "signal_kind": "near_incident",
            "ingest_type": "json",
            "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            "active": False,
            "tier": "curated",
        },
    ]

    return [source for source in sources if source.get("active")]