import json
import re
from datetime import datetime
from html import unescape
from urllib.request import urlopen

import feedparser
import requests
import trafilatura
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
_TITLE_CASE_TOKENS = {"INC", "CORP", "LTD", "CO", "COMPANY", "CORPORATION"}


def _title_case_word(word):
    """
    Decide casing for a single token. Order of precedence:
    1. Corporate suffixes (Inc, Corp, Ltd) -> title-case.
    2. Known keep-upper tokens (LLC, USA, etc.) -> upper.
    3. Already mixed-case -> leave alone.
    4. All-caps with non-alpha (AT&T, 8-K) -> preserved.
    5. All-caps short (<=3) -> preserved (IBM, NCR, HP, SEC).
    6. All-caps longer -> title-case (EQUIFAX, HONEYWELL).
    """
    bare = word.rstrip(".,;:")
    upper = bare.upper()

    if upper in _TITLE_CASE_TOKENS:
        return word.title()

    if upper in _KEEP_UPPER_TOKENS:
        return word.upper()

    if not bare.isupper():
        return word

    if not bare.isalpha():
        return word

    if len(bare) <= 3:
        return word

    return word.title()


def _title_case_company_name(name):
    """
    SEC display_names come in legal SCREAMING_CAPS. Title-case the all-caps
    tokens that look like real words (EQUIFAX, HONEYWELL, INTERNATIONAL),
    keep acronyms (IBM, NCR, SEC, AT&T) intact, leave mixed-case alone.
    Safe to apply to whole sentences from SEC summaries.
    """
    if not name:
        return name
    return " ".join(_title_case_word(w) for w in name.split())


_US_STATE_CODES = {
    "AL", "AK", "AZ", "AR", "CA", "CO", "CT", "DE", "FL", "GA",
    "HI", "ID", "IL", "IN", "IA", "KS", "KY", "LA", "ME", "MD",
    "MA", "MI", "MN", "MS", "MO", "MT", "NE", "NV", "NH", "NJ",
    "NM", "NY", "NC", "ND", "OH", "OK", "OR", "PA", "RI", "SC",
    "SD", "TN", "TX", "UT", "VT", "VA", "WA", "WV", "WI", "WY",
    "DC", "PR",
}


_SIC_TO_INDUSTRY_HINT = {
    "Technology": "Filer is a technology company.",
    "Healthcare": "Filer is a healthcare provider.",
    "Financial Services": "Filer is a financial services company.",
    "Education": "Filer is an education provider.",
    "Government": "Filer is a government agency.",
    "Energy": "Filer is an energy company.",
    "Transportation": "Filer is a transportation and logistics company.",
    "Media": "Filer is a media company.",
}


def _industry_from_sic(sic_code):
    """
    Map a SEC SIC code to our industry taxonomy. Returns None for SIC ranges
    that don't fit (e.g. industrial manufacturing, retail) — caller falls
    through to the regular extraction pipeline.
    """
    if not sic_code:
        return None
    try:
        sic = int(sic_code)
    except (ValueError, TypeError):
        return None

    if (
        7370 <= sic <= 7379
        or sic in {3576, 3577, 3578, 3669, 3674, 3825, 3827}
        or 4810 <= sic <= 4829
    ):
        return "Technology"
    if 6000 <= sic <= 6799:
        return "Financial Services"
    if 8000 <= sic <= 8099 or 2830 <= sic <= 2839:
        return "Healthcare"
    if 8200 <= sic <= 8299:
        return "Education"
    if 9100 <= sic <= 9999:
        return "Government"
    if 1300 <= sic <= 1389 or 4900 <= sic <= 4999:
        return "Energy"
    if 4000 <= sic <= 4789 or sic in {3711, 3713, 3714, 3715}:
        return "Transportation"
    if 2700 <= sic <= 2799 or 4830 <= sic <= 4899:
        return "Media"
    return None


_SEC_DOC_MAX_BYTES = 750_000


def _fetch_sec_filing_document(cik, accession_no_dash, primary_filename, user_agent):
    """
    Fetch a specific filing document by filename. Skips files larger than
    _SEC_DOC_MAX_BYTES (10-Q/10-K full-XBRL bodies are multi-megabyte).
    Returns raw HTML text or None on any failure.
    """
    if not primary_filename:
        return None
    try:
        doc_url = (
            f"https://www.sec.gov/Archives/edgar/data/{int(cik)}/"
            f"{accession_no_dash}/{primary_filename}"
        )
        head = requests.head(
            doc_url,
            headers={"User-Agent": user_agent},
            timeout=10,
            allow_redirects=True,
        )
        if head.status_code != 200:
            return None
        size = int(head.headers.get("Content-Length") or 0)
        if size and size > _SEC_DOC_MAX_BYTES:
            return None

        doc_resp = requests.get(
            doc_url,
            headers={"User-Agent": user_agent},
            timeout=20,
        )
        doc_resp.raise_for_status()
        return doc_resp.text
    except (requests.RequestException, ValueError, KeyError, TypeError):
        return None


def _strip_html_to_text(html):
    text = unescape(html)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def _extract_cyber_disclosure_text(html, max_chars=2500):
    """
    Pull a clean prose excerpt of a cyber disclosure from a filing document.
    Tries Item 1.05 first (8-K main bodies), falls back to the first
    cyber-keyword paragraph (press-release exhibits like EX-99.1).
    """
    if not html:
        return None

    text = _strip_html_to_text(html)
    if not text:
        return None

    item_105 = re.search(
        r"Item\s*1\.05[\.\s]*Material\s+Cybersecurity\s+Incidents?[\.\s]*"
        r"(.+?)"
        r"(?=Item\s+\d+\.\d+\b|SIGNATURES?\b|\bPursuant to the requirements\b)",
        text,
        re.IGNORECASE | re.DOTALL,
    )
    if item_105:
        body = item_105.group(1).strip()
        if len(body) >= 80:
            if len(body) > max_chars:
                body = body[:max_chars].rsplit(" ", 1)[0] + " [...]"
            return body

    # Fallback for press-release exhibits: walk sentences, accumulate from the
    # first one mentioning a cyber keyword until we have substantive prose.
    sentences = re.split(r"(?<=[.!?])\s+", text)
    cyber_terms = re.compile(
        r"\b(cyber|cybersecurity|unauthorized\s+access|data\s+breach|"
        r"ransomware|threat\s+actor|incident|exfiltrat)\b",
        re.IGNORECASE,
    )
    collected = []
    started = False
    for sentence in sentences:
        if not started and not cyber_terms.search(sentence):
            continue
        started = True
        collected.append(sentence)
        joined_len = sum(len(s) + 1 for s in collected)
        if joined_len >= max_chars:
            break
        if len(collected) >= 12:
            break
    if collected:
        body = " ".join(collected).strip()
        if len(body) >= 100:
            if len(body) > max_chars:
                body = body[:max_chars].rsplit(" ", 1)[0] + " [...]"
            return body
    return None


def _summary_from_disclosure_body(body, max_chars=400):
    """
    Pick a clean opening summary from an extracted disclosure body.
    """
    if not body:
        return None
    sentences = re.split(r"(?<=[.!?])\s+", body)
    summary = ""
    for sentence in sentences:
        if len(summary) + len(sentence) + 1 > max_chars and summary:
            break
        summary = (summary + " " + sentence).strip()
    if not summary:
        summary = body[:max_chars].rsplit(" ", 1)[0] + "..."
    return summary


def _primary_filename_from_hit_id(hit_id):
    """
    EDGAR full-text search hits come keyed as "<accession>:<filename>".
    Extract the filename half so we fetch the exact document the search matched.
    """
    if not hit_id or ":" not in hit_id:
        return None
    return hit_id.split(":", 1)[1].strip() or None


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

    seen_accession = set()

    for hit in data.get("hits", {}).get("hits", []):
        src = hit.get("_source", {}) or {}
        display_names = src.get("display_names") or []
        file_date = src.get("file_date")
        adsh = src.get("adsh")
        ciks = src.get("ciks") or []
        items_disclosed = src.get("items") or []
        primary_filename = _primary_filename_from_hit_id(hit.get("_id"))

        if not display_names or not file_date or not adsh:
            continue

        # Item 1.05 (Material Cybersecurity Incidents) is the SEC's required
        # designation for cyber disclosures since Dec 2023. Filings without
        # 1.05 in their items list are typically earnings releases, risk-factor
        # mentions, or M&A docs that just include the phrase as boilerplate.
        if "1.05" not in items_disclosed:
            continue

        # Multiple hits per filing (8-K body + each exhibit) — dedupe.
        if adsh in seen_accession:
            continue
        seen_accession.add(adsh)

        raw_company = display_names[0]
        company_name = re.sub(r"\s*\([^)]*\)\s*", "", raw_company).strip()
        company_name = company_name.rstrip(".,;:").strip()
        company_name = _title_case_company_name(company_name)
        if not company_name:
            continue

        sics = src.get("sics") or []
        industry = _industry_from_sic(sics[0]) if sics else None
        industry_hint = _SIC_TO_INDUSTRY_HINT.get(industry, "")

        biz_states = src.get("biz_states") or []
        country_hint = ""
        if biz_states and biz_states[0] in _US_STATE_CODES:
            country_hint = "Filer is based in the United States."

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
        template_parts = [
            f"{company_name} disclosed a data breach in a Form 8-K filing "
            f"with the SEC on {file_date}.",
            "Filed in a statement to investors.",
        ]
        if country_hint:
            template_parts.append(country_hint)
        if industry_hint:
            template_parts.append(industry_hint)
        template_parts.append(
            "Direct primary-source disclosure from the affected company "
            "under SEC reporting rules."
        )
        template_summary = " ".join(template_parts)

        disclosure_body = None
        if cik and accession_no_dash and primary_filename:
            html = _fetch_sec_filing_document(
                cik, accession_no_dash, primary_filename, user_agent
            )
            disclosure_body = _extract_cyber_disclosure_text(html)

        if disclosure_body:
            summary = (
                _summary_from_disclosure_body(disclosure_body) or template_summary
            )
            content_parts = [
                f"{company_name} — cybersecurity disclosure "
                f"(8-K, filed {file_date}):",
                disclosure_body,
            ]
            if country_hint:
                content_parts.append(country_hint)
            if industry_hint:
                content_parts.append(industry_hint)
            content_parts.append(
                "Direct primary-source disclosure from the affected company "
                "under SEC reporting rules."
            )
            content = "\n\n".join(content_parts)
        else:
            summary = template_summary
            content = template_summary

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


_ARTICLE_FETCH_TIMEOUT = 10
_ARTICLE_MAX_CHARS = 5000
_FETCH_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; CyberBLUF/1.0)"}


def _fetch_article_body(url):
    """
    Fetch the full article body from a URL using trafilatura.
    Returns extracted text or None if the fetch fails or is blocked.
    """
    try:
        resp = requests.get(
            url,
            timeout=_ARTICLE_FETCH_TIMEOUT,
            headers=_FETCH_HEADERS,
            allow_redirects=True,
        )
        if resp.status_code != 200:
            return None
        text = trafilatura.extract(
            resp.text,
            include_comments=False,
            include_tables=False,
        )
        if not text or len(text) < 100:
            return None
        return text[:_ARTICLE_MAX_CHARS].strip()
    except Exception:
        return None


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


_CONTENT_THIN_THRESHOLD = 300


def enrich_article_content():
    """
    Fetch full article body for RSS articles that have thin content.

    Runs after ingest and before process. Articles that are blocked or fail
    are left with content_enriched=False so the next pipeline run retries.
    """
    candidates = RawArticle.query.filter(
        RawArticle.source_type == "rss",
        RawArticle.content_enriched == False,  # noqa: E712
    ).all()

    enriched = 0
    for article in candidates:
        body = _fetch_article_body(article.article_url)
        if body:
            article.content = body
            article.content_enriched = True
            enriched += 1
        else:
            # Mark enriched even on failure if content is already substantial,
            # so we don't keep retrying articles that will never be fetchable.
            if article.content and len(article.content) >= _CONTENT_THIN_THRESHOLD:
                article.content_enriched = True

    db.session.commit()
    return {"candidates": len(candidates), "enriched": enriched}