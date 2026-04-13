def load_active_sources():
    """
    Curated high-signal source set for primary cyber incident discovery.

    Keep this intentionally small while validating feed quality.
    """

    return [
        {
            "name": "the-record-cybercrime",
            "type": "rss",
            "url": "https://therecord.media/news/cybercrime/feed",
            "active": True,
            "tier": "core",
        },
        {
            "name": "bleepingcomputer",
            "type": "rss",
            "url": "https://www.bleepingcomputer.com/feed/",
            "active": True,
            "tier": "core",
        },
    ]