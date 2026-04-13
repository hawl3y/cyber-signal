def load_active_sources():
    """
    Return active ingestion sources.
    Incident-focused starter set only.
    """
    return [
        {
            "name": "the-record-cybercrime",
            "type": "rss",
            "url": "https://therecord.media/news/cybercrime/feed",
            "active": True,
        },
        {
            "name": "cisa-cybersecurity-advisories",
            "type": "rss",
            "url": "https://www.cisa.gov/rss.xml",
            "active": True,
        },
    ]