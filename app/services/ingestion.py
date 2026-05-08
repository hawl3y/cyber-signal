import json
import re
from datetime import datetime
from html import unescape
from urllib.request import urlopen

import feedparser
import requests
from flask import current_app

from app.extensions import db
from app.models import RawArticle


def _clean_html_text(value):
    """
    Strip HTML tags and normalize whitespace from feed content.
    """
    if not value:
        return ""

    text = unescape(value)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _normalized_domain_from_url(url):
    return (
        (url or "")
        .replace("https://", "")
        .replace("http://", "")
        .split("/")[0]
    )


def _build_raw_article_payload(
    *,
    source,
    article_url,
    title,
    summary,
    published_at,
    fetched_at,
    ingestion_batch_id,
    publisher=None,
    content=None,
):
    return {
        "source_type": source.get("ingest_type") or source.get("type"),
        "source_name": source.get("name"),
        "source_url": source.get("url"),
        "publisher": publisher or source.get("name"),
        "article_url": article_url,
        "title": title,
        "normalized_title": title.lower().strip(),
        "summary": summary,
        "content": content if content is not None else summary,
        "normalized_domain": _normalized_domain_from_url(source.get("url")),
        "ingestion_batch_id": ingestion_batch_id,
        "published_at": published_at,
        "fetched_at": fetched_at,
        "language": "en",
        "processing_status": "pending",
    }


def _fetch_rss_items(source):
    """
    Fetch and normalize raw RSS items from a configured source.
    """
    feed = feedparser.parse(source.get("url"))
    fetched_at = datetime.utcnow()
    ingestion_batch_id = fetched_at.strftime("%Y%m%d%H%M%S")
    recent_cutoff = fetched_at.replace(hour=0, minute=0, second=0, microsecond=0)
    items = []

    for entry in feed.entries:
        article_url = entry.get("link") or entry.get("id")
        title = _clean_html_text(entry.get("title", ""))
        summary = _clean_html_text(entry.get("summary", ""))

        if source.get("name") == "cisa-alerts-advisories":
            raw_summary = _clean_html_text(entry.get("summary", ""))
            raw_summary = re.sub(r"^\s*View CSAF Summary\s*", "", raw_summary, flags=re.IGNORECASE)
            raw_summary = re.sub(r"\s+", " ", raw_summary).strip()

            sentence_parts = re.findall(r".+?[.!?](?=\s|$)", raw_summary)

            if sentence_parts:
                summary = sentence_parts[0].strip()
            else:
                summary = None

            if not summary or len(summary) < 40:
                summary = f"{title} vulnerability advisory from CISA."
        else:
            summary = _clean_html_text(entry.get("summary", ""))

        if not article_url or not title:
            continue

        published_at = fetched_at
        if entry.get("published_parsed"):
            published_at = datetime(*entry.published_parsed[:6])

        items.append(
            _build_raw_article_payload(
                source=source,
                article_url=article_url,
                title=title,
                summary=summary,
                content=summary,
                published_at=published_at,
                fetched_at=fetched_at,
                ingestion_batch_id=ingestion_batch_id,
                publisher=_clean_html_text(feed.feed.get("title") or source.get("name")),
            )
        )

    return items


def _fetch_cisa_kev_items(source):
    """
    Fetch KEV JSON and map entries into thin near-incident article records.

    This intentionally creates a normalized article-like record so the current
    MVP pipeline can ingest KEV without introducing a second pipeline yet.
    """
    fetched_at = datetime.utcnow()
    ingestion_batch_id = fetched_at.strftime("%Y%m%d%H%M%S")
    items = []

    with urlopen(source.get("url")) as response:
        payload = json.load(response)

    vulnerabilities = payload.get("vulnerabilities", [])
    catalog_version = payload.get("catalogVersion")
    publisher = "CISA Known Exploited Vulnerabilities"

    for entry in vulnerabilities:
        cve_id = (entry.get("cveID") or "").strip()
        vendor_project = (entry.get("vendorProject") or "").strip()
        product = (entry.get("product") or "").strip()
        vulnerability_name = (entry.get("vulnerabilityName") or "").strip()
        short_description = _clean_html_text(entry.get("shortDescription", ""))

        if not cve_id:
            continue

        display_name_parts = []
        if vendor_project:
            display_name_parts.append(vendor_project)
        if product and product.lower() != vendor_project.lower():
            display_name_parts.append(product)

        display_name = " ".join(part for part in display_name_parts if part).strip()
        if not display_name:
            display_name = "KEV Entry"

        cleaned_vulnerability_name = vulnerability_name
        if cleaned_vulnerability_name:
            prefix_to_strip = display_name.lower().strip()
            lowered_vuln_name = cleaned_vulnerability_name.lower().strip()

            if prefix_to_strip and lowered_vuln_name.startswith(prefix_to_strip):
                cleaned_vulnerability_name = cleaned_vulnerability_name[len(display_name):].strip(" -|:")

        if cleaned_vulnerability_name:
            title = f"{display_name} {cleaned_vulnerability_name} ({cve_id})"
        else:
            title = f"{display_name} Vulnerability ({cve_id})"

        title = re.sub(r"\s+", " ", title).strip()

        summary = short_description.strip()
        if summary:
            summary = re.sub(r"\s+", " ", summary)

            sentence_parts = re.findall(r".+?[.!?](?=\s|$)", summary)
            if sentence_parts:
                summary = " ".join(sentence_parts[:2]).strip()
            elif len(summary) > 320:
                trimmed = summary[:320].rstrip()
                if " " in trimmed:
                    trimmed = trimmed.rsplit(" ", 1)[0]
                summary = trimmed.rstrip(" ,;:") + "."
        else:
            summary = f"{display_name} was added to the CISA KEV catalog under {cve_id}."

        article_url = f"{source.get('url')}#{cve_id}"

        date_added = entry.get("dateAdded")
        published_at = fetched_at
        if date_added:
            try:
                published_at = datetime.fromisoformat(date_added)
            except ValueError:
                published_at = fetched_at

        if (fetched_at - published_at).days > 90:
            continue

        content = " ".join(
            part for part in [
                summary,
                f"CVE: {cve_id}" if cve_id else None,
                f"Vendor: {vendor_project}" if vendor_project else None,
                f"Product: {product}" if product else None,
                f"Catalog version: {catalog_version}" if catalog_version else None,
            ]
            if part
        )

        items.append(
            _build_raw_article_payload(
                source=source,
                article_url=article_url,
                title=title,
                summary=summary,
                content=content,
                published_at=published_at,
                fetched_at=fetched_at,
                ingestion_batch_id=ingestion_batch_id,
                publisher=publisher,
            )
        )

    return items


_KEEP_UPPER_TOKENS = {"LLC", "PLC", "GMBH", "USA", "UK", "EU", "II", "III", "IV", "VI"}


def _title_case_company_name(name):
    """
    SEC display_names come in legal/SCREAMING_CAPS format. Title-case all-caps
    tokens for display, but keep known uppercase suffixes (LLC, PLC, etc.) and
    leave already-mixed-case tokens alone.
    """
    if not name:
        return name

    parts = []
    for word in name.split():
        upper_stripped = word.rstrip(".,;:").upper()
        if upper_stripped in _KEEP_UPPER_TOKENS:
            parts.append(word.upper())
        elif word.isupper():
            parts.append(word.title())
        else:
            parts.append(word)
    return " ".join(parts)


def _fetch_sec_edgar_cyber_items(source):
    """
    Fetch SEC 8-K filings that disclose a material cybersecurity incident.

    Uses the EDGAR full-text search index for the canonical legal phrase
    used in Item 1.05 (and older Item 8.01) cyber filings. The filer is
    the victim by definition, so the title/summary uses regex-friendly
    language so deterministic extraction picks up victim_org_name.
    """
    fetched_at = datetime.utcnow()
    ingestion_batch_id = fetched_at.strftime("%Y%m%d%H%M%S")
    items = []

    user_agent = current_app.config.get(
        "SEC_USER_AGENT", "Cyber Signal cyber-signal@example.com"
    )

    response = requests.get(
        "https://efts.sec.gov/LATEST/search-index",
        params={
            "q": '"material cybersecurity incident"',
            "forms": "8-K",
            "size": 100,
        },
        headers={"User-Agent": user_agent},
        timeout=30,
    )
    response.raise_for_status()
    data = response.json()

    publisher = "SEC EDGAR (8-K cyber disclosures)"

    for hit in data.get("hits", {}).get("hits", []):
        src = hit.get("_source", {}) or {}
        display_names = src.get("display_names") or []
        file_date = src.get("file_date")
        adsh = src.get("adsh")
        ciks = src.get("ciks") or []

        if not display_names or not file_date or not adsh:
            continue

        raw_company = display_names[0]
        company_name = re.sub(r"\s*\([^)]*\)\s*", "", raw_company).strip()
        company_name = company_name.rstrip(".,;:").strip()
        company_name = _title_case_company_name(company_name)
        if not company_name:
            continue

        cik = (ciks[0] if ciks else None)
        accession_no_dash = adsh.replace("-", "") if adsh else ""

        if cik and accession_no_dash:
            article_url = (
                f"https://www.sec.gov/Archives/edgar/data/{int(cik)}/"
                f"{accession_no_dash}/{adsh}-index.htm"
            )
        else:
            article_url = (
                "https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany"
                f"&CIK={cik or ''}&type=8-K"
            )

        try:
            published_at = datetime.fromisoformat(file_date)
        except (ValueError, TypeError):
            published_at = fetched_at

        if (fetched_at - published_at).days > 60:
            continue

        title = f"{company_name} discloses breach in SEC 8-K filing"
        summary = (
            f"{company_name} disclosed a data breach in a Form 8-K filing "
            f"with the SEC on {file_date}. Filed in a statement to investors. "
            f"Direct primary-source disclosure from the affected company under "
            f"SEC reporting rules."
        )

        items.append(
            _build_raw_article_payload(
                source=source,
                article_url=article_url,
                title=title,
                summary=summary,
                content=summary,
                published_at=published_at,
                fetched_at=fetched_at,
                ingestion_batch_id=ingestion_batch_id,
                publisher=publisher,
            )
        )

    return items


def fetch_source_items(source):
    """
    Fetch and normalize items from a configured source based on ingest type.
    """
    ingest_type = source.get("ingest_type", "rss")

    if ingest_type == "rss":
        return _fetch_rss_items(source)

    if ingest_type == "json" and source.get("name") == "cisa-kev":
        return _fetch_cisa_kev_items(source)

    if ingest_type == "sec_edgar_cyber":
        return _fetch_sec_edgar_cyber_items(source)

    raise ValueError(
        f"Unsupported source ingest_type '{ingest_type}' for source '{source.get('name')}'"
    )


def save_raw_article(article):
    """
    Save a normalized article to the database if it does not already exist.
    """
    existing = RawArticle.query.filter_by(article_url=article.get("article_url")).first()
    if existing:
        return existing

    raw_article = RawArticle(**article)

    db.session.add(raw_article)
    db.session.commit()

    return raw_article