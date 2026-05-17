import re

from app.extensions import db
from app.models import RawArticle, ArticleExtraction
from app.utils.sources import get_source_config
from app.services.taxonomy import normalize_attack_type, normalize_event_anchor_type


def _combined_article_text(article):
    return " ".join(
        [
            (article.title or "").strip(),
            (article.summary or "").strip(),
            (article.content or "").strip(),
        ]
    ).lower()

_SUMMARY_ABBREVS = {
    'dr', 'mr', 'mrs', 'ms', 'st', 'vs', 'no', 'inc', 'corp', 'ltd', 'co',
    'dept', 'govt', 'fig', 'jan', 'feb', 'mar', 'apr', 'jun', 'jul', 'aug',
    'sep', 'oct', 'nov', 'dec', 'ave', 'blvd', 'est', 'approx', 'prof', 'gen',
    'rep', 'sen', 'sgt', 'capt', 'lt', 'col', 'maj',
}


def _trim_to_complete_sentence(text):
    if not text:
        return text
    if re.search(r'[.!?]["\')]?\s*$', text):
        return text
    last_sent_end = None
    for m in re.finditer(r'[.!?]["\')]?(?=\s+[A-Z])', text):
        preceding_word = re.search(r'(\w+)\s*$', text[:m.start()])
        if preceding_word:
            word = preceding_word.group(1)
            if len(word) == 1 and word.isupper():
                continue
            if word.lower() in _SUMMARY_ABBREVS:
                continue
        last_sent_end = m.end()
    if last_sent_end:
        return text[:last_sent_end].strip()
    return None


def _clean_summary_text(value):
    if not value:
        return None

    cleaned = value.strip()
    cleaned = re.sub(r"\s*\[\.\.\.\]\s*$", "", cleaned).strip()
    cleaned = re.sub(r"\s*(?:\.{2,}|…)\s*$", "", cleaned).strip()
    cleaned = re.sub(r"\s+", " ", cleaned).strip()

    return _trim_to_complete_sentence(cleaned) or None


def _build_short_event_summary(article):
    summary = _clean_summary_text(article.summary)
    if summary:
        return summary

    content = _clean_summary_text(article.content)
    if not content:
        return None

    first_sentence = re.split(r"(?<=[.!?])\s+", content, maxsplit=1)[0].strip()
    return first_sentence or None

def _is_plausible_org_candidate(value):
    if not value:
        return False

    cleaned = re.sub(r"\s+", " ", str(value).strip())
    if not cleaned:
        return False

    lowered = cleaned.lower()
    words = lowered.split()

    action_terms = {
        "affects",
        "affected",
        "breached",
        "hacked",
        "hit",
        "targeted",
        "attacked",
        "exposed",
        "leaked",
        "stolen",
        "pushed",
        "push",
        "infected",
        "compromised",
        "extorted",
        "disrupted",
        "running",
        "using",
    }

    generic_tail_terms = {
        "suite",
        "plugin",
        "plugins",
        "package",
        "packages",
        "tool",
        "tools",
        "system",
        "systems",
        "platform",
        "platforms",
        "app",
        "apps",
        "application",
        "applications",
        "sites",
        "website",
        "websites",
        "accounts",
        "users",
        "customers",
        "data",
        "records",
    }

    allowed_org_suffixes = {
        "bank",
        "group",
        "university",
        "hospital",
        "clinic",
        "school",
        "college",
        "telecom",
        "telecommunications",
        "communications",
        "insurance",
        "laboratory",
        "laboratories",
        "agency",
        "ministry",
        "department",
        "authority",
        "city",
        "municipality",
        "network",
        "networks",
        "corp",
        "corporation",
        "inc",
        "ltd",
        "llc",
        "plc",
    }

    if any(term in words for term in action_terms):
        return False

    if len(words) >= 3 and words[-1] in generic_tail_terms and words[-1] not in allowed_org_suffixes:
        return False

    if len(words) >= 2 and words[-2] in action_terms:
        return False

    # Document headers and advisory titles contain colons; org names never do.
    if ":" in cleaned:
        return False

    # These words open clauses, documents, or describe fake artifacts —
    # they never begin a real org name. This is a structural rule, not a blocklist.
    non_org_first_words = {
        # Action gerunds — sentence starters in advisory titles
        "defending", "targeting", "exploiting", "using", "abusing",
        "protecting", "securing", "warning", "alerting", "exposing",
        "bypassing", "hijacking", "stealing", "deploying", "tracking",
        # Inauthenticity adjectives
        "fake", "false",
        # Document structure terms
        "executive", "summary", "advisory",
    }
    if words and words[0] in non_org_first_words:
        return False

    uppercase_tokens = re.findall(r"\b[A-Z][A-Za-z0-9&._-]*\b", cleaned)
    if not uppercase_tokens and not re.search(r"[A-Z]{2,}", cleaned) and not cleaned[0].isupper():
        return False

    return True

_GENERIC_ORG_TERMINAL_WORDS = {
    "agency", "bank", "company", "cybersecurity", "firm", "government", "group",
    "hospital", "ministry", "organization", "organisation", "provider",
    "school", "service", "university", "vendor",
}

# First-word prefixes that signal a generic description rather than a named org.
# "cybersecurity firm" → generic; "Popular Bank" → named org (popular not here).
# Only words that can never plausibly open a real organization's proper name belong here.
_GENERIC_DESCRIPTOR_PREFIXES = frozenset({
    # Industry/category — describe what the org does, not its name
    "cybersecurity", "security", "technology", "tech", "software", "it",
    "cloud", "digital", "online", "internet", "financial", "healthcare",
    "medical", "pharmaceutical", "managed",
    # Scope/geography — describe coverage, not a proper name
    "local", "regional", "global", "international", "federal", "state",
    "municipal", "public", "government",
    # Status — the org is anonymous or unknown
    "unnamed", "unknown",
    # Articles/determiners that survive the "the"-strip in _clean_org_name
    "a", "an",
})


def _is_generic_org_descriptor(value):
    tokens = value.lower().split()
    if not tokens or tokens[-1] not in _GENERIC_ORG_TERMINAL_WORDS:
        return False
    if len(tokens) == 1:
        return True
    # For 2–3 token strings, only treat as generic when the first token is a known
    # category/scope descriptor. This lets named orgs like "Popular Bank" or
    # "First National Bank" through while still blocking "cybersecurity firm",
    # "local hospital", "government agency", etc.
    return len(tokens) <= 3 and tokens[0] in _GENERIC_DESCRIPTOR_PREFIXES


ORG_CLAUSE_BOUNDARY_RE = re.compile(
    r"\s+(?:"
    r"affects?|affected|impacting|impacts?|hits?|hit|after|via|through|using|on|"
    r"linked\s+to|with|in|as|amid|following|from|that|which|where|when|"
    r"according\s+to|said|says|confirmed|confirms|reported|reportedly"
    r")\b",
    flags=re.IGNORECASE,
)

def _clean_org_name(value):
    if not value:
        return None

    cleaned = value.strip(" -,:;\"'[]{}“”‘’")
    cleaned = re.sub(r"\s+", " ", cleaned).strip()

    if not cleaned:
        return None

    cleaned = re.sub(r"^(?:the)\s+", "", cleaned, flags=re.IGNORECASE)
    # Truncate at sentence boundary: "DoD. The attack..." → "DoD"
    # Safe for abbreviations like "U.S. Navy" because those aren't followed by sentence-starter words.
    _before = cleaned
    cleaned = re.sub(
        r'\.\s+(?:The|A|An|This|These|Those|It|They|He|She|We|Its)\b.*$',
        '', cleaned, flags=re.IGNORECASE,
    )
    # Only strip trailing period when the regex actually consumed a sentence
    # continuation — not for legitimate trailing periods in org names like "Co."
    if cleaned != _before:
        cleaned = cleaned.rstrip('.')
    cleaned = ORG_CLAUSE_BOUNDARY_RE.split(cleaned, maxsplit=1)[0].strip()
    cleaned = re.sub(r"\s+", " ", cleaned).strip(" -,:;\"'[]{}“”‘’")

    if not cleaned:
        return None

    cleaned = re.sub(
        r"^(?:(?:[A-Za-z][A-Za-z0-9&._-]*\s+){0,2}"
        r"(?:company|organization|firm|vendor|provider|developer|publisher|operator|platform|exchange|chain|group|maker|giant)\s+)"
        r"(?=[A-Z])",
        "",
        cleaned,
        flags=re.IGNORECASE,
    ).strip()

    cleaned = re.sub(
        r"^([A-Z][A-Za-z0-9&._-]*(?:\s+[A-Z][A-Za-z0-9&._-]*){0,3})\s+[a-z][a-z0-9&._-]*(?:\s+[a-z][a-z0-9&._-]*)*$",
        r"\1",
        cleaned,
    ).strip()

    lowered = cleaned.lower()

    blocked_exact = {
        "data",
        "breach",
        "hack",
        "attack",
        "ransomware",
        "cyberattack",
        "cyber",
        "accounts",
        "users",
        "customers",
        "employees",
        "systems",
        "platform",
        "suite",
        "plugin",
        "plugins",
        "report",
        "reports",
        "analysis",
        "hackers",
        "threat actors",
        "official website",
        "download links",
        "new",
        "official",
        "multiple",
        "several",
        "hundreds",
        "thousands",
        "millions",
        # Pronouns — never a victim org name
        "they",
        "he",
        "she",
        "it",
        "we",
        "them",
        "their",
        # Standalone words that can prefix real org names ("Popular Bank", "Local Motors")
        # but are never org names on their own. Mirrors _GENERIC_DESCRIPTOR_PREFIXES —
        # when _clean_org_name strips the trailing terminal word (e.g. "hospital" from
        # "Local hospital"), the prefix would otherwise pass as a valid victim.
        "popular", "major", "widely", "commonly", "newly", "recently",
        "legitimate", "notorious",
        "local", "regional", "global", "international",
        "federal", "state", "municipal", "public", "government",
        "unnamed", "unknown",
        "cybersecurity", "security", "technology", "tech", "software",
        "cloud", "digital", "online", "internet",
        "financial", "healthcare", "medical", "pharmaceutical", "managed",
    }

    if not cleaned or lowered in blocked_exact:
        return None

    if len(cleaned) <= 2:
        return None

    if len(cleaned.split()) > 6:
        return None

    if not _is_plausible_org_candidate(cleaned):
        return None

    return cleaned

def _normalize_org_name(value):
    if not value:
        return None

    normalized = value.strip().lower()
    normalized = normalized.replace("-", " ")
    normalized = normalized.replace("&", " and ")
    normalized = re.sub(r"'s\b", "", normalized)
    normalized = re.sub(r"[^a-z0-9\s]", " ", normalized)
    normalized = re.sub(
        r"\b(inc|llc|ltd|corp|corporation|company|co|group|plc|sa|ag|gmbh|nv|bv"
        r"|services|solutions|systems|holdings|enterprises|international|technologies)\b",
        "",
        normalized,
    )
    normalized = re.sub(r"\s+", " ", normalized).strip()

    return normalized or None


def _extract_victim_org_name(article):
    title = (article.title or "").strip()
    summary = (article.summary or "").strip()
    # Content is only searched with high-precision relationship patterns to avoid
    # false positives from generic body text.
    content = (article.content or "").strip()[:2000]

    if not title:
        return None

    if title.lower().startswith("webinar:"):
        return None

    # High-precision patterns safe to run against full article body.
    # These express explicit product→company relationships — low false-positive risk.
    body_only_patterns = [
        r"\b(?:created by|developed by|owned by|operated by|provided by|made by)\s+([A-Z][A-Za-z0-9._-]+(?:\s+[A-Z][A-Za-z0-9._-]*){0,2})\b",
        r"\b([A-Z][A-Za-z0-9._-]+(?:\s+[A-Z][A-Za-z0-9._-]*){0,2}),?\s+(?:maker|developer|creator|provider|vendor)\s+of\b",
        r"\bparent\s+(?:firm|company|organization|corp|corporation)\s+([A-Z][A-Za-z0-9._-]+(?:\s+[A-Z][A-Za-z0-9._-]*){0,2})\b",
        r"\b([A-Z][A-Za-z0-9._-]+(?:\s+[A-Z][A-Za-z0-9._-]*){0,2})'s\s+(?:platform|service|software|system|product|application|app|tool|portal|website|network|infrastructure|database|plugin|suite|suite of tools)\b",
        # "X, a wholly owned subsidiary of [Parent]" — X is the org that was breached
        r"\b([^,.;:]+?),\s+a\s+(?:wholly\s+)?owned\s+subsidiary\s+of\b",
    ]

    target_patterns = [
        # Strong: subject of a disclosure verb at the start of the headline.
        # Uses [^,.;:]+? (not [A-Z]...) so it handles non-ASCII org names (e.g. Škoda, Über).
        r"^\s*([^,.;:]+?)\s+(?:confirms|confirmed|discloses|disclosed|acknowledges|acknowledged|admits|admitted|warns|reported|notified)\b",
        # Resolution-phase headlines: "X reaches [ransom] agreement/deal/settlement with [threat actor]"
        # Allow 0-2 optional words between "reaches" and "agreement/deal/settlement" (e.g. "Ransom Agreement")
        r"^\s*([A-Z][A-Za-z0-9._-]+(?:\s+[A-Z][A-Za-z0-9._-]*){0,2})\s+(?:reaches?|reached)\s+(?:\S+\s+){0,2}(?:agreement|deal|settlement)\b.*\s+with\b",
        # "X pays/paid ransom to [actor]" — victim paying extortion
        r"^\s*([A-Z][A-Za-z0-9._-]+(?:\s+[A-Z][A-Za-z0-9._-]*){0,2})\s+(?:pays?|paid)\s+ransom\b",
        # "fined [Org] £/$/€..." — regulatory fine confirms the org was the breach victim
        r"\bfined\s+([A-Z][A-Za-z0-9._-]+(?:\s+[A-Z][A-Za-z0-9._-]*){0,3})\s+[£$€¥]",
        # "X site/system hacked" — requires a target noun so "Russia Hacked Routers" (actor)
        # is not mistaken for a victim construction.
        r"^([A-Z][A-Za-z0-9._-]+(?:\s+[A-Z][A-Za-z0-9._-]*){0,2})\s+(?:site|system|network|server|database|website|download manager|repository)\s+(?:hacked|breached|hijacked)(?:\s+to\b|\s+by\b|\s+in\b|\s*$)",
        # Supply-chain: "Official OrgName ProductEcosystem package/plugin compromised"
        # The org is the affected vendor; the skip word is the product ecosystem name.
        r"^(?:[Oo]fficial\s+)?([A-Z][A-Za-z0-9._-]+(?:\s+[A-Z][A-Za-z0-9._-]*){0,1})\s+\w+\s+(?:package|plugin|library|module|extension)\s+(?:compromised|backdoored|tampered|poisoned|hacked)\b",
        # body_only_patterns are also included here so they apply to title/summary
        r"\b(?:created by|developed by|owned by|operated by|provided by|made by)\s+([A-Z][A-Za-z0-9._-]+(?:\s+[A-Z][A-Za-z0-9._-]*){0,2})\b",
        r"\b([A-Z][A-Za-z0-9._-]+(?:\s+[A-Z][A-Za-z0-9._-]*){0,2}),?\s+(?:maker|developer|creator|provider|vendor)\s+of\b",
        # "X parent firm/company Org" — e.g. "Canvas parent firm Instructure"
        r"\bparent\s+(?:firm|company|organization|corp|corporation)\s+([A-Z][A-Za-z0-9._-]+(?:\s+[A-Z][A-Za-z0-9._-]*){0,2})\b",
        # "Org's [platform/service/product/...]" — possessive product ownership
        r"\b([A-Z][A-Za-z0-9._-]+(?:\s+[A-Z][A-Za-z0-9._-]*){0,2})'s\s+(?:platform|service|software|system|product|application|app|tool|portal|website|network|infrastructure|database|plugin|suite|suite of tools)\b",
        # "X source code/data/system breach [claimed/reported by]" — X is the victim.
        # Require 4+ char first token to avoid sentence-start words like "New".
        r"^\s*([A-Z][A-Za-z0-9._-]{3,}(?:\s+[A-Z][A-Za-z0-9._-]*){0,2})\s+(?:source code|data|systems?|network)\s+breach\b",
        # "Canvas Breach Disrupts Schools..." — product/platform name followed by "Breach" then active verb
        r"^\s*([A-Z][A-Za-z0-9._-]{3,}(?:\s+[A-Z][A-Za-z0-9._-]*){0,2})\s+[Bb]reach\s+(?:[Dd]isrupt|[Ee]xpose|[Hh]it|[Ff]orce|[Ss]hut|[Kk]nock)\w*\b",
        r"\b(?:breach|hack|attack|cyberattack|cyber attack|data theft)\s+at\s+(?:[a-z][a-z0-9&._' -]*\s+){0,5}([A-Z][A-Za-z0-9&._'-]*(?:\s+[A-Z][A-Za-z0-9&._'-]*){0,3})\b",
        r"\b([A-Z][A-Za-z0-9&._'-]*(?:\s+[A-Z][A-Za-z0-9&._'-]*){0,3})\s+hacker\s+claims\s+data\s+theft\b",
        r"\b(?:breach|hack|attack|cyberattack|cyber attack|ransomware attack)\s+(?:at|on|against|of)\s+([^,.;:]+)",
        r"\b(?:breach|attack|cyberattack|cyber attack|ransomware attack)\s+affecting\s+(?:the\s+)?([^,.;:]+)",
        r"\b(?:confirms|confirmed|reports|reported|discloses|disclosed)\s+(?:a\s+)?(?:data\s+)?breach\s+(?:at|of)\s+([^,.;:]+)",
        r"\b([A-Z][A-Za-z0-9&._' -]{1,80}?)\s+(?:confirms|confirmed|acknowledges|acknowledged)\s+(?:the\s+)?(?:incident|cyberattack|cyber attack|attack|breach)\b",
        r"\b([^,.;:]+?)\s+(?:was|were|has been|have been)\s+(?:breached|hacked|attacked|targeted|compromised|disrupted|extorted)\b",
        r"\b([^,.;:]+?)\s+(?:confirms|confirmed|reports|reported|discloses|disclosed)\s+(?:a\s+)?(?:data\s+)?breach\b",
        r"\b([^,.;:]+?)\s+(?:was\s+|were\s+)?(?:hit by|suffered|suffers)\s+(?:a\s+)?(?:ransomware attack|cyberattack|cyber attack|data breach|security breach)\b",
        r"\b([^,.;:]+?)\s+(?:falls victim to|fell victim to)\s+(?:a\s+)?(?:ransomware attack|cyberattack|cyber attack|data breach|security breach)\b",
        # Handles org names containing periods (e.g. "Schulte-Lindhorst GmbH & Co.") where
        # [^,.;:] would stop at the embedded period before reaching "hit by"/"was hit by".
        r"^(.+?)\s+(?:was\s+)?hit\s+by\s+(?:a\s+)?ransomware\s+attack\b",
        # Recovery/aftermath headline: "[Org] [recovery state] after [attack type]"
        # e.g. "Medtech giant Stryker fully operational after data-wiping attack"
        r"^\s*([^,.;:]+?)\s+(?:fully\s+)?(?:operational|restored|back\s+online|back\s+up|recovers?|recovered|resuming?|resumed?)\s+after\b",
    ]

    # Captures ending in audience nouns (e.g. "Armenian users", "Russian citizens")
    # describe who was affected, never the victim org. Drop the whole match.
    audience_tail_re = re.compile(
        r"\b(?:users?|customers?|citizens?|people|visitors?|clients?|"
        r"residents?|nationals?|workers?|members?|subscribers?|patients?|"
        r"students?|employees?|consumers?|tenants?|guests?|riders?|"
        r"shoppers?|viewers?|readers?|listeners?)\s*$",
        flags=re.IGNORECASE,
    )

    blocked_action_phrase = re.compile(
        r"\bto\s+(?:steal|deploy|push|harvest|leak|breach|hack|target|attack|compromise|disrupt|extort)\b",
        flags=re.IGNORECASE,
    )

    generic_org_terms = {
        "agency",
        "bank",
        "company",
        "firm",
        "government",
        "group",
        "hospital",
        "ministry",
        "organization",
        "organisation",
        "provider",
        "school",
        "service",
        "university",
        "vendor",
    }

    actor_start_terms = {
        "hackers", "researchers", "attackers", "threat actors", "cybercriminals",
        "criminals", "nation-state", "adversaries", "scammers",
    }

    def extract_candidates(text, patterns=None):
        candidates = []

        for pattern in (patterns if patterns is not None else target_patterns):
            for match in re.finditer(pattern, text, flags=re.IGNORECASE):
                raw_capture = (match.group(1) or "").strip()
                if audience_tail_re.search(raw_capture):
                    continue

                candidate = _clean_org_name(raw_capture)
                if not candidate:
                    continue

                # re.IGNORECASE makes [A-Z] match lowercase too; org names always start uppercase.
                if not candidate[0].isupper():
                    continue

                if blocked_action_phrase.search(candidate):
                    continue

                if any(token.lower() in actor_start_terms for token in candidate.split()):
                    continue

                candidates.append(candidate)

        return candidates

    def is_generic_descriptor(value):
        if not value:
            return True
        return _is_generic_org_descriptor(value)

    # Official alert sources (NCSC, CISA) use advisory titles as document headers,
    # not incident descriptions — "Defending against China-nexus..." is not a victim.
    # Skip title/summary extraction entirely; only accept explicit company relationships
    # from the article body via body_only_patterns.
    source_config = get_source_config(article.source_name) if article.source_name else {}
    is_official_alert = (source_config or {}).get("source_class") == "official_alert"

    title_candidates = [] if is_official_alert else extract_candidates(title)
    summary_candidates = [] if is_official_alert else (extract_candidates(summary) if summary else [])
    # body_only_patterns express explicit company relationships (parent firm, maker of,
    # owned by, etc.) which are more authoritative than implicit title/summary patterns.
    # Run them first so "Canvas parent firm Instructure" beats "Canvas" from the title.
    content_candidates = extract_candidates(content, patterns=body_only_patterns) if content else []

    # Supply-chain headline: the entity named before "supply chain attack" in the title
    # is the direct victim. Check the title explicitly here before summary candidates,
    # because the summary often only names the disclosing org ("OpenAI confirms...").
    if not is_official_alert:
        sc_match = re.search(
            r"\bin\s+([A-Z][A-Za-z0-9._-]+(?:\s+[A-Z][A-Za-z0-9._-]*){0,2})\s+supply[\s-]chain\s+attack\b",
            title,
            flags=re.IGNORECASE,
        )
        if sc_match:
            candidate = _clean_org_name(sc_match.group(1))
            if candidate and not is_generic_descriptor(candidate):
                return candidate

        # "[Org] Supply Chain Attack Hits/Affects/..." — title-subject form where the
        # compromised vendor leads the headline rather than following "in".
        # e.g. "TanStack Supply Chain Attack Hits Two OpenAI Employee Devices"
        sc_subject_match = re.search(
            r"^([A-Z][A-Za-z0-9._-]+(?:\s+[A-Z][A-Za-z0-9._-]*){0,2})\s+supply[\s-]chain\s+attack\b",
            title,
            flags=re.IGNORECASE,
        )
        if sc_subject_match:
            candidate = _clean_org_name(sc_subject_match.group(1))
            if candidate and not is_generic_descriptor(candidate):
                return candidate

        # "X confirms [Product] data breach" — the product/service named after "confirms"
        # is the victim, not X (the disclosing entity). Body patterns extract X via
        # "X's service" possessive, so this must return early before body candidates.
        cd_match = re.search(
            r"\bconfirms?\s+([A-Z][A-Za-z0-9._-]+(?:\s+(?!(?:data|breach)\b)[A-Z][A-Za-z0-9._-]*){0,2})\s+(?:data\s+)?breach\b",
            title,
            flags=re.IGNORECASE,
        )
        if cd_match:
            candidate = _clean_org_name(cd_match.group(1))
            if candidate and not is_generic_descriptor(candidate):
                return candidate

    for candidate in content_candidates:
        if not is_generic_descriptor(candidate):
            return candidate

    for candidate in summary_candidates:
        if not is_generic_descriptor(candidate):
            return candidate

    for candidate in title_candidates:
        if not is_generic_descriptor(candidate):
            return candidate

    return None


def _extract_exploitation_subject(article):
    title = (article.title or "").strip()

    if not title:
        return None

    patterns = [
        r"^(?:Critical|High-severity|High severity|Severe|New)\s+([A-Z][A-Za-z0-9._-]*(?:\s+[A-Z][A-Za-z0-9._-]*){0,2})\s+.*\bflaw\b",
        r"^([A-Z][A-Za-z0-9._-]*(?:\s+[A-Z][A-Za-z0-9._-]*){0,2})\s+.*\bflaw\b",
    ]

    for pattern in patterns:
        match = re.search(pattern, title)
        if match:
            candidate = _clean_org_name(match.group(1))
            if candidate:
                return candidate

    return None


def _clean_anchor_candidate(value):
    if not value:
        return None

    cleaned = re.sub(r"\s+", " ", str(value)).strip(" -,:;\"'[]{}“”‘’")

    if not cleaned:
        return None

    if len(cleaned) < 2 or len(cleaned) > 120:
        return None

    blocked = {
        "critical",
        "high-severity",
        "new",
        "severe",
        "flaw",
        "vulnerability",
        "bug",
        "attack",
        "attacks",
        "campaign",
        "ransomware",
        "malware",
    }

    if cleaned.lower() in blocked:
        return None

    blocked_actor_terms = {"official", "hackers", "researchers", "attackers", "threat", "criminals", "adversaries"}
    if any(w.lower() in blocked_actor_terms for w in cleaned.split()):
        return None

    # These words open advisory titles, clauses, or describe fake artifacts —
    # they never start a useful anchor name (matches the same guard in _is_plausible_org_candidate).
    _anchor_blocked_first_words = {
        "defending", "targeting", "exploiting", "using", "abusing",
        "protecting", "securing", "warning", "alerting", "exposing",
        "bypassing", "hijacking", "stealing", "deploying", "tracking",
        "fake", "false",
        "executive", "summary", "advisory",
    }
    first_word = cleaned.split()[0].lower() if cleaned.split() else ""
    if first_word in _anchor_blocked_first_words:
        return None

    return cleaned


# Words that indicate vulnerability/impact type, not a vendor name.
# Used to stop vendor extraction at the right boundary.
_VULN_TYPE_STOP_WORDS = frozenset({
    "multiple", "improper", "missing", "insufficient", "incorrect",
    "arbitrary", "cross-site", "remote", "local", "server-side",
})


def _extract_cisa_vendor(title):
    """
    Extract the vendor name from a CISA advisory or KEV title.
    e.g. 'ABB Ability Symphony Plus Engineering' → 'ABB'
         'Johnson Controls CEM AC2000'           → 'Johnson Controls'
         'Apple Multiple Products Buffer Overflow' → 'Apple'
         'BeyondTrust Remote Support'             → 'BeyondTrust'
    """
    words = title.split()
    if not words:
        return title
    first = words[0]
    # All-caps first word (ABB, NSA, MAXHUB) is a company abbreviation.
    if first.isupper() and len(first) >= 3:
        return first
    # Otherwise take up to 2 words, stopping before product codes
    # (words with digits, all-caps acronyms ≥3 chars, special chars, or vuln-type adjectives).
    vendor_words = [first]
    if len(words) > 1:
        w = words[1]
        is_product_code = (
            any(c.isdigit() for c in w)
            or (w.isupper() and len(w) >= 3)
            or "&" in w
            or "/" in w
            or w.lower() in _VULN_TYPE_STOP_WORDS
        )
        if not is_product_code and w.lower() != first.lower():
            vendor_words.append(w)
    return " ".join(vendor_words)


def _extract_event_anchor(article, victim_org_name=None, actor_name=None):
    if victim_org_name:
        return victim_org_name, "organization"

    title = (article.title or "").strip()
    summary = (article.summary or "").strip()
    text = f"{title} {summary}"

    cve_match = re.search(r"\b(CVE-\d{4}-\d+)\b", text, flags=re.IGNORECASE)
    if cve_match:
        return cve_match.group(1).upper(), "vulnerability"

    descriptive_incident_patterns = [
        r"^(.+?)\s+(?:heaped|enabled|launched|conducted|carried out|fueled)\s+attacks?\b",
        r"^(.+?)\s+(?:hit|hits|targeted|attacked|breached|compromised)\b",
    ]

    for pattern in descriptive_incident_patterns:
        match = re.search(pattern, title, flags=re.IGNORECASE)
        if match:
            candidate = _clean_anchor_candidate(match.group(1))
            if candidate:
                return candidate, "campaign"

    campaign_patterns = [
        r"\bin\s+['\"]?([^'\"]+?)['\"]?\s+ransomware\s+attacks?\b",
        r"\b([^,.;:]+?)\s+campaign\b",
    ]

    for pattern in campaign_patterns:
        match = re.search(pattern, title, flags=re.IGNORECASE)
        if match:
            candidate = _clean_anchor_candidate(match.group(1))
            if candidate:
                return candidate, "campaign"

    if article.source_name in {"cisa-kev", "cisa-alerts-advisories"} and title:
        return title, "product_or_platform"

    product_patterns = [
        r"\b(?:flaw|vulnerability|bug)\s+in\s+([^,.;:]+)",
        r"\b([^,.;:]+?)\s+(?:flaw|vulnerability|bug)\b",
        r"\b([^,.;:]+?)\s+(?:zero-day|0-day)\b",
    ]

    for pattern in product_patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            candidate = _clean_anchor_candidate(match.group(1))
            if candidate:
                return candidate, "product_or_platform"

    subject = _extract_exploitation_subject(article)
    if subject:
        return subject, "product_or_platform"

    if actor_name:
        return actor_name, "actor"

    return None, "unknown"


def _extract_industry(text):
    target_context_patterns = [
        (r"\battacks?\s+(?:on|against)\s+[^.;:]*\b(government|govt|agency|ministry|municipalit(?:y|ies)|federal|state government|department)\b", "Government"),
        (r"\battacks?\s+(?:on|against)\s+[^.;:]*\b(hospital|hospitals|healthcare|clinic|health system|medical)\b", "Healthcare"),
        (r"\battacks?\s+(?:on|against)\s+[^.;:]*\b(school|schools|university|universities|college|education|educational|student|campus|district)\b", "Education"),
        (r"\battacks?\s+(?:on|against)\s+[^.;:]*\b(bank|banks|financial|credit union|insurance|brokerage|payment processor)\b", "Financial Services"),
        (r"\battacks?\s+(?:on|against)\s+[^.;:]*\b(utility|utilities|power grid|water utility|water company|oil pipeline|gas pipeline|energy provider|energy company)\b", "Energy"),
        (r"\battacks?\s+(?:on|against)\s+[^.;:]*\b(airport|airline|aviation|rail|railway|transit|metro|shipping|logistics|freight|port authority)\b", "Transportation"),
        (r"\battacks?\s+(?:on|against)\s+[^.;:]*\b(newspaper|news outlet|media company|broadcaster|television network|radio station|publisher)\b", "Media"),
        (r"\battacks?\s+(?:on|against)\s+[^.;:]*\b(manufacturer|manufacturing|factory|industrial|electronics maker|contract manufacturer)\b", "Manufacturing"),
        (r"\battacks?\s+(?:on|against)\s+[^.;:]*\b(retailer|retail chain|supermarket|department store|e-commerce|online store)\b", "Retail"),
        (r"\battacks?\s+(?:on|against)\s+[^.;:]*\b(telecom|telecommunications|isp|internet service provider|mobile carrier|wireless provider)\b", "Telecommunications"),
        (r"\battacks?\s+(?:on|against)\s+[^.;:]*\b(hotel|casino|resort|hospitality)\b", "Hospitality"),
        (r"\battacks?\s+(?:on|against)\s+[^.;:]*\b(law firm|legal services|accounting firm|professional services)\b", "Legal"),
    ]

    for pattern, industry in target_context_patterns:
        if re.search(pattern, text, flags=re.IGNORECASE):
            return industry

    industry_keywords = {
        "Healthcare": [
            "hospital",
            "healthcare",
            "patient",
            "medical",
            "clinic",
            "health system",
            "health service",
            "pharmaceutical",
            "pharma",
            "biotech",
            "medtech",
            "health care",
        ],
        "Energy": [
            "energy company",
            "energy sector",
            "energy provider",
            "utility company",
            "utility provider",
            "power grid",
            "power plant",
            "substation",
            "water utility",
            "water treatment",
            "water company",
            "water works",
            "gas utility",
            "oil pipeline",
            "gas pipeline",
            "critical pipeline",
        ],
        "Education": [
            "school",
            "university",
            "college",
            "education",
            "educational",
            "edtech",
            "student",
            "campus",
            "district",
        ],
        "Government": [
            "government",
            "agency",
            "ministry",
            "public sector",
            "municipal",
            "city of ",
            "county",
            "state government",
            "federal",
            "department of",
            "public service",
            "township",
            "parish",
        ],
        "Transportation": [
            "airport",
            "airline",
            "aviation",
            "rail",
            "railway",
            "transit",
            "metro",
            "port authority",
            "shipping",
            "logistics",
            "freight",
            "electric bicycle",
            "electric bike",
            "e-bike",
            "ebike",
            "motorcycle",
            "vehicle",
            "automotive",
            "fleet",
        ],
        "Manufacturing": [
            "contract manufacturer",
            "electronics manufacturer",
            "manufacturing company",
            "manufacturing firm",
            "contract electronics",
            "industrial manufacturer",
        ],
        "Media": [
            "newspaper",
            "news outlet",
            "media company",
            "media firm",
            "media group",
            "media outlet",
            "news organization",
            "publishing company",
            "broadcaster",
            "television network",
            "radio station",
            "publisher",
        ],
        "Financial Services": [
            "bank",
            "banking",
            "financial institution",
            "financial services",
            "financial sector",
            "atm",
            "cryptocurrency exchange",
            "crypto exchange",
            "crypto platform",
            "crypto protocol",
            "crypto bridge",
            "defi platform",
            "defi protocol",
            "defi project",
            "defi attack",
            "defi hack",
            "decentralized finance",
            "web3 platform",
            "blockchain protocol",
            "flash loan",
            "rug pull",
            "rugpull",
            "smart contract",
            "crypto heist",
            "crypto theft",
            "fintech",
            "payment processor",
            "credit union",
            "brokerage",
            "insurance company",
            "insurer",
        ],
        "Retail": [
            "retailer",
            "retail chain",
            "retail store",
            "retail company",
            "retail group",
            "e-commerce",
            "ecommerce",
            "online retailer",
            "online store",
            "online marketplace",
            "supermarket",
            "grocery chain",
            "department store",
            "clothing retailer",
            "fashion retailer",
        ],
        "Telecommunications": [
            "telecom",
            "telecommunications",
            "internet service provider",
            "mobile carrier",
            "wireless carrier",
            "wireless provider",
            "broadband provider",
            "mobile network",
            "phone company",
            " isp ",
            "telco",
        ],
        "Legal": [
            "law firm",
            "legal services",
            "legal firm",
            "law practice",
            "attorneys at law",
            "solicitors",
            "accounting firm",
            "audit firm",
            "professional services firm",
        ],
        "Hospitality": [
            "hotel chain",
            "hotel group",
            "hotel operator",
            "casino operator",
            "casino resort",
            "resort chain",
            "hospitality company",
            "hospitality group",
            "hospitality industry",
        ],
        "Technology": [
            "software provider",
            "software vendor",
            "technology",
            "tech company",
            "tech firm",
            "it provider",
            "cloud",
            "saas",
            "hosting provider",
            "managed service provider",
            "msp",
            "it services",
            "data center",
            "software",
            "suite",
            "control panel",
            "platform",
            "plugin",
            "browser",
            "developer tool",
            "application framework",
            "firmware",
            "virtual machines",
            "vendor:",
            "product:",
            "video game developer",
            "gaming",
            "game studio",
            "gpu",
            "semiconductor",
            "chipmaker",
            "cpanel",
            "telematics",
            "fleet management",
            "fleet management company",
            "gps tracking",
            "tracking platform",
            # Consumer tech / malware campaign signals
            "macos",
            "mac malware",
            "malvertising",
            "infostealer",
            "stealer malware",
            "ai chatbot",
            "google ads",
            "npm package",
            "pypi package",
        ],
    }

    for industry, keywords in industry_keywords.items():
        if any(keyword in text for keyword in keywords):
            return industry

    # Only use org-type patterns as a last resort — they match quoted sources too broadly
    # to be used before keyword matching.
    organization_type_patterns = [
        (
            r"\b(?:cybersecurity|security|threat intelligence|endpoint security|network security)\s+"
            r"(?:company|firm|vendor|provider|platform)\b",
            "Technology",
        ),
        (
            r"\b(?:company|firm|vendor|provider|platform)\s+"
            r"(?:specializing in|focused on|providing|offering)\s+"
            r"(?:cybersecurity|security|threat intelligence|endpoint security|network security)\b",
            "Technology",
        ),
    ]

    for pattern, industry in organization_type_patterns:
        if re.search(pattern, text, flags=re.IGNORECASE):
            return industry

    return None

_COUNTRY_TO_REGION = {
    "United States": "North America",
    "Canada": "North America",
    "Mexico": "North America",
    "United Kingdom": "Europe",
    "Netherlands": "Europe",
    "Germany": "Europe",
    "France": "Europe",
    "Italy": "Europe",
    "Spain": "Europe",
    "Portugal": "Europe",
    "Belgium": "Europe",
    "Switzerland": "Europe",
    "Austria": "Europe",
    "Poland": "Europe",
    "Sweden": "Europe",
    "Norway": "Europe",
    "Finland": "Europe",
    "Denmark": "Europe",
    "Ireland": "Europe",
    "Romania": "Europe",
    "Czech Republic": "Europe",
    "Ukraine": "Europe",
    "Russia": "Europe",
    "China": "Asia",
    "Taiwan": "Asia",
    "Japan": "Asia",
    "India": "Asia",
    "Singapore": "Asia",
    "South Korea": "Asia",
    "Hong Kong": "Asia",
    "Thailand": "Asia",
    "Vietnam": "Asia",
    "Indonesia": "Asia",
    "Philippines": "Asia",
    "Malaysia": "Asia",
    "Australia": "Oceania",
    "New Zealand": "Oceania",
    "Brazil": "South America",
    "Argentina": "South America",
    "Chile": "South America",
    "Colombia": "South America",
    "Peru": "South America",
    "South Africa": "Africa",
    "Nigeria": "Africa",
    "Kenya": "Africa",
    "Egypt": "Africa",
    "Israel": "Middle East",
    "United Arab Emirates": "Middle East",
    "Saudi Arabia": "Middle East",
    "Qatar": "Middle East",
    "Turkey": "Middle East",
    "Iran": "Middle East",
    "Iraq": "Middle East",
    "Jordan": "Middle East",
    "Lebanon": "Middle East",
    "Kuwait": "Middle East",
    "Oman": "Middle East",
    "Bahrain": "Middle East",
    "Yemen": "Middle East",
    "Armenia": "Asia",
    "Azerbaijan": "Asia",
    "Georgia": "Asia",
    "Kazakhstan": "Asia",
    "Pakistan": "Asia",
    "Bangladesh": "Asia",
    "Sri Lanka": "Asia",
    "Nepal": "Asia",
    "Belarus": "Europe",
    "Estonia": "Europe",
    "Latvia": "Europe",
    "Lithuania": "Europe",
    "Slovakia": "Europe",
    "Slovenia": "Europe",
    "Croatia": "Europe",
    "Serbia": "Europe",
    "Bulgaria": "Europe",
    "Hungary": "Europe",
    "Greece": "Europe",
    "Iceland": "Europe",
    "Luxembourg": "Europe",
    "Malta": "Europe",
    "Morocco": "Africa",
    "Algeria": "Africa",
    "Tunisia": "Africa",
    "Ethiopia": "Africa",
    "Ghana": "Africa",
    "Tanzania": "Africa",
    "Zimbabwe": "Africa",
    "Costa Rica": "North America",
    "Panama": "North America",
    "Cuba": "North America",
    "Dominican Republic": "North America",
    "Jamaica": "North America",
    "Venezuela": "South America",
    "Ecuador": "South America",
    "Bolivia": "South America",
    "Uruguay": "South America",
    "Paraguay": "South America",
}


def region_for_country(country):
    """Return the canonical region for a country name, or None if unknown."""
    if not country:
        return None
    return _COUNTRY_TO_REGION.get(country)


def _extract_geography(text, fallback_text=None):
    """
    Extract geography from text.

    target_phrase_patterns scan the full `text` (title+summary+content) for
    attack-context phrases like "attacks on X country".

    The flat keyword scan (any country mention) uses `fallback_text` when
    provided — typically title+summary only — to avoid picking up incidental
    country mentions in article bodies (e.g. a US company listing its global
    offices).
    """
    country = None
    region = None
    scan_text = fallback_text if fallback_text is not None else text

    # Strip "Armenian users", "Russian citizens", etc. so a nationality adjective
    # describing who was affected doesn't get treated as the victim's country.
    scan_text = re.sub(
        r'\b\w+(?:ian|ish|ese|an)\s+(?:users?|customers?|citizens?|people|residents?|'
        r'nationals?|workers?|members?|subscribers?|patients?|students?|employees?)\b',
        '',
        scan_text,
        flags=re.IGNORECASE,
    )

    geography_map = [
        (["united states", "u.s.", "u.s.a.", "usa", "american"], "United States", "North America"),
        # US states — breach articles often name the state rather than the country
        (["california", "texas", "new york", "new jersey", "virginia", "washington state",
           "washington, d.c.", "washington dc", "florida", "illinois", "georgia", "pennsylvania",
           "massachusetts", "ohio", "michigan", "north carolina", "arizona", "colorado",
           "maryland", "nevada", "minnesota", "indiana", "tennessee", "missouri", "wisconsin",
           "connecticut", "oregon", "utah", "louisiana", "alabama", "kentucky",
           "oklahoma", "kansas", "arkansas", "iowa", "mississippi", "nebraska",
           "idaho", "new mexico", "hawaii", "alaska", "west virginia"], "United States", "North America"),
        (["canada", "canadian"], "Canada", "North America"),
        (["mexico", "mexican"], "Mexico", "North America"),

        (["united kingdom", "uk ", " uk", "britain", "british", "england"], "United Kingdom", "Europe"),
        (["netherlands", "dutch"], "Netherlands", "Europe"),
        (["germany", "german"], "Germany", "Europe"),
        (["france", "french"], "France", "Europe"),
        (["italy", "italian"], "Italy", "Europe"),
        (["spain", "spanish"], "Spain", "Europe"),
        (["portugal", "portuguese"], "Portugal", "Europe"),
        (["belgium", "belgian"], "Belgium", "Europe"),
        (["switzerland", "swiss"], "Switzerland", "Europe"),
        (["austria", "austrian"], "Austria", "Europe"),
        (["poland", "polish"], "Poland", "Europe"),
        (["sweden", "swedish"], "Sweden", "Europe"),
        (["norway", "norwegian"], "Norway", "Europe"),
        (["finland", "finnish"], "Finland", "Europe"),
        (["denmark", "danish"], "Denmark", "Europe"),
        (["ireland", "irish"], "Ireland", "Europe"),
        (["romania", "romanian"], "Romania", "Europe"),
        (["czech republic", "czechia", "czech"], "Czech Republic", "Europe"),
        (["ukraine", "ukrainian"], "Ukraine", "Europe"),
        (["russia", "russian"], "Russia", "Europe"),

        (["china", "chinese"], "China", "Asia"),
        (["taiwan", "taiwanese"], "Taiwan", "Asia"),
        (["japan", "japanese"], "Japan", "Asia"),
        (["india", "indian"], "India", "Asia"),
        (["singapore"], "Singapore", "Asia"),
        (["south korea", "korea", "korean"], "South Korea", "Asia"),
        (["hong kong"], "Hong Kong", "Asia"),
        (["thailand", "thai"], "Thailand", "Asia"),
        (["vietnam", "vietnamese"], "Vietnam", "Asia"),
        (["indonesia", "indonesian"], "Indonesia", "Asia"),
        (["philippines", "philippine"], "Philippines", "Asia"),
        (["malaysia", "malaysian"], "Malaysia", "Asia"),

        (["australia", "australian"], "Australia", "Oceania"),
        (["new zealand"], "New Zealand", "Oceania"),

        (["brazil", "brazilian"], "Brazil", "South America"),
        (["argentina", "argentinian", "argentine"], "Argentina", "South America"),
        (["chile", "chilean"], "Chile", "South America"),
        (["colombia", "colombian"], "Colombia", "South America"),
        (["peru", "peruvian"], "Peru", "South America"),

        (["south africa"], "South Africa", "Africa"),
        (["nigeria", "nigerian"], "Nigeria", "Africa"),
        (["kenya", "kenyan"], "Kenya", "Africa"),
        (["egypt", "egyptian"], "Egypt", "Africa"),

        (["israel", "israeli"], "Israel", "Middle East"),
        (["uae", "united arab emirates"], "United Arab Emirates", "Middle East"),
        (["saudi arabia", "saudi"], "Saudi Arabia", "Middle East"),
        (["qatar"], "Qatar", "Middle East"),
        (["turkey", "turkish"], "Turkey", "Middle East"),
        (["iran", "iranian"], "Iran", "Middle East"),
        (["iraq", "iraqi"], "Iraq", "Middle East"),

        (["armenia", "armenian"], "Armenia", "Central Asia"),
        (["azerbaijan"], "Azerbaijan", "Central Asia"),
        (["kazakhstan"], "Kazakhstan", "Central Asia"),
        (["uzbekistan"], "Uzbekistan", "Central Asia"),
        (["pakistan", "pakistani"], "Pakistan", "Asia"),
        (["bangladesh"], "Bangladesh", "Asia"),
        (["afghanistan"], "Afghanistan", "Asia"),
    ]

    target_phrase_patterns = [
        r"\battacks?\s+(?:on|against)\s+([^.;:]+)",
        r"\btarget(?:ing|ed)\s+([^.;:]+)",
        r"\bcampaign(?:s)?\s+against\s+([^.;:]+)",
        r"\bmalware\s+used\s+in\s+attacks?\s+(?:on|against)\s+([^.;:]+)",
        # "X based in [Country]" / "partner based in Armenia" — identifies the location of
        # the breached entity when country appears only in the article body, not title/summary.
        r"\bbased\s+in\s+([^.;:,]+)",
    ]

    _audience_in_span_re = re.compile(
        r'\b\w+(?:ian|ish|ese|an)\s+(?:users?|customers?|citizens?|people|residents?|'
        r'nationals?|workers?|members?|subscribers?|patients?|students?|employees?)\b',
        re.IGNORECASE,
    )

    target_spans = []
    for pattern in target_phrase_patterns:
        for match in re.finditer(pattern, text, flags=re.IGNORECASE):
            span = match.group(1).strip()
            if not span:
                continue
            if re.search(r'\b\w+-language\s+(?:software|systems?|apps?|tools?|platforms?|code)\b', span, re.IGNORECASE):
                continue
            # Strip audience-adjective contexts ("targeting Armenian users") from spans
            # so the nationality doesn't register as the attack geography.
            span = _audience_in_span_re.sub('', span).strip()
            if span:
                target_spans.append(span)

    for span in target_spans:
        for keywords, mapped_country, mapped_region in geography_map:
            if any(keyword in span for keyword in keywords):
                return {
                    "country": mapped_country,
                    "region": mapped_region,
                    "city": None,
                }

    for keywords, mapped_country, mapped_region in geography_map:
        if any(keyword in scan_text for keyword in keywords):
            country = mapped_country
            region = mapped_region
            break

    # Fallback: scan article body for company-nationality descriptions.
    # "West Pharma is a publicly traded American manufacturing company" → United States.
    # Guard against actor descriptions ("LockBit is a Russian ransomware firm") by
    # skipping spans that contain threat actor terminology.
    if country is None:
        _actor_terms = frozenset([
            "cybercrime", "ransomware", "malware", "hacking", "espionage",
            "extortion", "criminal", "threat actor", "hacker",
        ])
        for match in re.finditer(
            r"\bis\s+an?\s+([^.;:]+?)\s+(?:company|corporation|corp|firm|manufacturer|"
            r"organisation|organization|enterprise|conglomerate|subsidiary)\b",
            text,
            re.IGNORECASE,
        ):
            span = match.group(1).strip()
            if any(term in span for term in _actor_terms):
                continue
            for keywords, mapped_country, mapped_region in geography_map:
                if any(keyword in span for keyword in keywords):
                    country = mapped_country
                    region = mapped_region
                    break
            if country:
                break

    if country is None:
        region_map = [
            (["north america"], "North America"),
            (["south america", "latin america"], "South America"),
            (["europe", "european"], "Europe"),
            (["asia", "asia-pacific", "apac"], "Asia"),
            (["middle east"], "Middle East"),
            (["africa"], "Africa"),
            (["oceania"], "Oceania"),
            (["global attack", "worldwide attack", "international attack", "global campaign", "worldwide campaign"], "Global"),
        ]

        for keywords, mapped_region in region_map:
            if any(keyword in scan_text for keyword in keywords):
                region = mapped_region
                break

    return {
        "country": country,
        "region": region,
        "city": None,
    }

def _has_exploitation_signal(text):
    """
    Returns True when the text describes a confirmed cyber intrusion at any level
    of specificity. Covers both precise technical signals (CVE, exploit code) and
    generic incident language (hacked, cyberattack, unauthorized access).

    This function is the VERIS Hacking action catch-all: any article describing
    unauthorized technical access to systems should return True here if no more
    specific type (Ransomware, Financial Theft, Data Breach, etc.) was matched first.
    """
    if not text:
        return False

    patterns = [
        # Precise technical signals
        r"\bcve-\d{4}-\d+\b",
        r"\bexploit(?:ed|s|ing)?\b",
        r"\bexploitation\b",
        r"\bactively exploited\b",
        r"\bunder active exploitation\b",
        r"\bknown exploited vulnerability\b",
        r"\bpre-auth\b",
        r"\bremote code execution\b",
        r"\brce\b",
        r"\bzero.?day\b",
        r"\bvulnerability\b",
        r"\bpatch(?:ed)?\b",
        # Generic intrusion language — any confirmed unauthorized access
        # maps here when no more specific type was detected above.
        r"\bhacked\b",
        r"\bcyber.?attack\b",
        r"\bunauthorized access\b",
        r"\bsecurity incident\b",
        r"\bintrusion\b",
        r"\binfiltrat(?:ed|ion)\b",
        r"\bbroke into\b",
        r"\bgained access\b",
        r"\bcompromised (?:the |its |their )?\b(?:system|network|server|infrastructure|environment)\b",
        r"\battackers? (?:accessed|gained|obtained)\b",
    ]

    return any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns)

def get_ready_for_extraction():
    """
    Fetch articles ready for extraction.
    """
    return RawArticle.query.filter_by(processing_status="ready_for_extraction").all()


def run_rule_extraction(article):
    """
    First-pass deterministic extraction from article text.
    """
    text = _combined_article_text(article)

    victim_org_name = _extract_victim_org_name(article)

    source_config = get_source_config(article.source_name)
    signal_kind = source_config.get("signal_kind") if source_config else None

    if signal_kind == "activity":
        victim_org_name = None

    victim_org_normalized = _normalize_org_name(victim_org_name)

    # Infer industry from the victim org name itself — most reliable signal because
    # it reflects what the company IS, not what the article happens to mention.
    industry = None
    if victim_org_name:
        name_lower = victim_org_name.lower()
        if any(k in name_lower for k in [
            "pharmaceutical", "pharma", "biopharmaceutical", "biopharma",
            "hospital", "health", "medical", "clinic", "therapeutics",
            "biotech", "biologics", "healthcare",
        ]):
            industry = "Healthcare"
        elif any(k in name_lower for k in [
            "bank", "bancorp", "bancshares", "financial", "finance",
            "insurance", "capital", "investment", "credit union",
            "asset management", "brokerage", "mortgage",
            "bitcoin", "crypto", "blockchain", "defi", "dao",
            "payments", "fintech", "exchange", "wallet", "trading",
            "protocol", "bridge",
        ]):
            industry = "Financial Services"
        elif any(k in name_lower for k in [
            "university", "college", "school", "academy", "institute of technology",
            "polytechnic", "edu",
        ]):
            industry = "Education"
        elif any(k in name_lower for k in [
            "energy", "power", "electric", "utility", "utilities",
            "pipeline", "petroleum", "oil", "gas company", "water works",
        ]):
            industry = "Energy"
        elif any(k in name_lower for k in [
            "airline", "airways", "airport", "railway", "railroad",
            "transit", "shipping", "logistics", "freight",
            "auto", "automotive", "automobile", "motors", "vehicle",
        ]):
            industry = "Transportation"
        elif any(k in name_lower for k in [
            "manufacturing", "foxconn", "hon hai",
            "industrial systems", "industrial automation",
        ]):
            industry = "Manufacturing"
        elif any(k in name_lower for k in [
            "county", "municipality", "municipal", "city of", "department of",
            "ministry of", "federal", "government",
        ]):
            industry = "Government"
        elif any(k in name_lower for k in [
            "telecom", "telecommunications", "wireless", "mobile network",
            "broadband", "telco",
        ]):
            industry = "Telecommunications"
        elif any(k in name_lower for k in [
            "hotel", "resort", "casino", "hospitality",
        ]):
            industry = "Hospitality"
        elif any(k in name_lower for k in [
            "retail", "supermarket", "grocer",
        ]):
            industry = "Retail"

    victim_context_text = ""
    if victim_org_name:
        # Use title + summary only — full article content is too noisy for industry
        # classification because it often mentions industries the victim company
        # *serves* (e.g. Trellix serving government) rather than what it *is*.
        victim_context_text = " ".join([
            article.title or "",
            article.summary or "",
        ]).lower()

    if not industry:
        industry = _extract_industry(victim_context_text) if victim_context_text else None

    if not industry:
        # When no victim context is available, restrict to title+summary to avoid
        # incidental body-text mentions (e.g., "universities use Office 365") from
        # misclassifying the industry of broad-campaign articles.
        title_summary_text = " ".join([
            (article.title or "").strip(),
            (article.summary or "").strip(),
        ]).lower()
        industry = _extract_industry(title_summary_text)

    if not industry:
        # Restrict to title+summary: full body text is too noisy and causes incidental
        # mentions (e.g., "universities use Office 365") to misclassify the industry.
        title_summary = " ".join([
            article.title or "",
            article.summary or "",
        ]).lower()

        if any(term in title_summary for term in ["hospital", "healthcare", "medical", "medtech", "clinic"]):
            industry = "Healthcare"
        elif any(term in title_summary for term in ["school", "university", "education", "student"]):
            industry = "Education"
        elif any(term in title_summary for term in ["government", "ministry", "agency", "municipality", "city of"]):
            industry = "Government"
        elif any(term in title_summary for term in ["bank", "banking", "fintech", "payment processor", "credit union"]):
            industry = "Financial Services"
        elif any(term in title_summary for term in ["telecom", "telecommunications", "mobile carrier", "wireless carrier", "broadband provider", "internet service provider"]):
            industry = "Telecommunications"
        elif any(term in title_summary for term in ["hotel chain", "hotel group", "casino", "resort", "hospitality company", "hospitality group"]):
            industry = "Hospitality"
        elif any(term in title_summary for term in ["retailer", "retail chain", "supermarket", "e-commerce", "online retailer", "online store", "department store"]):
            industry = "Retail"
        elif any(term in title_summary for term in ["law firm", "legal services", "accounting firm", "professional services firm"]):
            industry = "Legal"
        elif any(term in title_summary for term in [
            "software vendor", "software provider", "tech company", "tech firm",
            "saas", "hosting provider", "managed service provider", "msp",
            "data center", "developer tool", "application framework",
            "web admin", "npm package", "pypi package", "package registry",
            "open-source", "open source software", "zero-day exploit",
            # Consumer tech / malware campaign signals
            "macos", "mac malware", "malvertising", "google ads",
            "infostealer", "stealer malware", "ai chatbot",
            "browser extension", "apple mac", "apple silicon",
        ]):
            industry = "Technology"

    if not industry:
        industry = "Unknown"

    # Named victims with no identifiable sector default to Technology — the most common
    # sector in cyber incidents and a better fallback than Unknown when content is thin.
    if industry == "Unknown" and victim_org_name:
        industry = "Technology"

    lead_text_for_geo = " ".join([
        (article.title or "").strip(),
        (article.summary or "").strip(),
    ]).lower()
    geography = _extract_geography(text, fallback_text=lead_text_for_geo)

    # SEC EDGAR 8-K filers are US-domiciled by definition.
    if article.source_name == "sec-edgar-cyber-8k" and not geography.get("country"):
        geography = {"country": "United States", "region": "North America", "city": None}

    title_summary_text = " ".join([
        (article.title or "").strip(),
        (article.summary or "").strip(),
    ]).lower()

    # Strip "anti-ransomware" before ransomware keyword matching to avoid false positives
    # on articles about ransomware defenses.
    text_for_ransomware = re.sub(r"\banti-ransomware\b", "", text, flags=re.IGNORECASE)

    # Activity signals (CISA advisories, KEV) describe vulnerability classes, not incident
    # delivery methods. Skip Ransomware/DDoS/Malware/Phishing for those sources to prevent
    # advisory boilerplate text (e.g. "phishing may be used to gain initial access") from
    # overriding the actual vulnerability classification.
    is_activity = signal_kind == "activity"

    # Title-level breach signals take precedence over body-text ransomware group descriptions.
    # "Trellix source code breach claimed by RansomHouse" → Data Breach, not Ransomware.
    title_lower = (article.title or "").lower()
    title_signals_breach = any(kw in title_lower for kw in [
        "data breach",
        "security breach",
        "source code breach",
        "breach of",
        "breach at",
        "breach disrupts",
        "breach exposes",
        # Data-theft outcome markers — outcome type beats initial-access vector
        "data leak",
        "data theft",
        " leak",
        "tb leak",
        "gb leak",
        "mb leak",
        "stolen data",
        "data stolen",
    ])

    # Title-level wiper/destructive signals prevent "sensitive data" negations in article body
    # ("no sensitive data was accessed") from incorrectly classifying as Data Breach.
    # "Medtech giant Stryker fully operational after data-wiping attack" → Malware, not Data Breach.
    title_signals_wiper = any(kw in title_lower for kw in [
        "data-wiping", "data wiping", "wiping attack", "wiper attack",
        "wiper malware", "disk wiper", "disk wiping", "wiping malware",
    ])

    # Attack type detection — ordered most-specific first per VERIS hierarchy.
    # See taxonomy.py for VERIS/DBIR provenance of each type.
    attack_type = "Unknown"

    # --- Supply Chain (VERIS: Hacking/Malware via third-party) ---
    # Checked first: describes the attack vector, not the payload. A supply chain
    # attack that also mentions ransomware stays Supply Chain.
    # Contextual phrases confined to title+summary — they appear in quoted expert
    # commentary in unrelated articles. Unambiguous technical indicators can use
    # full text since they never appear as business-context false positives.
    _sc_title_summary_phrases = [
        "supply chain attack", "supply chain compromise", "supply chain hack",
        "supply chain intrusion", "supply-chain attack", "supply chain infection",
        "attacked via supply chain",
    ]
    _sc_full_text_phrases = [
        "malicious package", "malicious update", "poisoned package",
        "dependency confusion", "compromised vendor", "third-party compromise",
    ]
    if not is_activity and (
        any(p in title_summary_text for p in _sc_title_summary_phrases)
        or any(p in text for p in _sc_full_text_phrases)
    ):
        attack_type = "Supply Chain"

    # --- Ransomware (VERIS: Malware/Ransomware | DBIR: Ransomware) ---
    elif not is_activity and not title_signals_breach and any(p in text_for_ransomware for p in [
        "ransomware", "ransom note", "ransom demand",
        "double extortion", "extortion gang", "encryptor",
    ]):
        attack_type = "Ransomware"

    # --- Financial Theft (VERIS: Hacking | DBIR: System Intrusion, financial) ---
    # Funds, cryptocurrency, or other monetary assets stolen. Distinct from Data Breach
    # (no personal data angle). Quantified loss phrases ("million stolen") are title/summary
    # only — they appear as historical context in full article bodies. Specific DeFi/heist
    # terms are low enough false-positive risk to check in full text.
    elif not is_activity and (
        any(p in title_summary_text for p in [
            # Quantified monetary loss
            "million stolen", "billion stolen", "million drained", "billion drained",
            "million in crypto", "million in bitcoin", "million in ethereum", "million in ether",
            "million worth of crypto",
            # Dollar amount as the outcome of a hack ("hacked for $625 million")
            "hacked for $", "stolen $", "theft of $",
            # Direct fund theft
            "funds stolen", "stolen funds", "crypto stolen", "cryptocurrency stolen",
            "funds drained", "drained funds", "assets stolen", "assets drained",
            "wallet drained", "treasury drained",
            # General financial crime
            "cyber heist", "crypto heist", "crypto theft", "cryptocurrency theft",
            "wire fraud", "bank fraud",
        ])
        or any(p in text for p in [
            # DeFi/Web3 attack patterns — unambiguous, safe in full text
            "flash loan", "flash-loan",
            "rug pull", "rugpull",
            "defi exploit", "defi hack", "defi attack",
            "bridge exploit", "bridge hack", "bridge attack",
            "smart contract exploit", "protocol exploit", "protocol hack",
            "drain attack", "drained the protocol",
        ])
    ):
        attack_type = "Financial Theft"

    # --- DDoS (VERIS: Hacking/DoS | DBIR: Denial of Service) ---
    elif not is_activity and any(p in text for p in [
        "ddos", "denial of service", "distributed denial of service",
        "botnet", "traffic flood",
    ]):
        attack_type = "DDoS"

    # --- Phishing (VERIS: Social | DBIR: Social Engineering) ---
    elif not is_activity and not title_signals_breach and any(p in text for p in [
        "phishing", "phishing-as-a-service", "spear-phishing",
        "credential harvesting", "malicious email",
        "business email compromise", "bec ",
        "vishing", "smishing", "spear phishing",
    ]):
        attack_type = "Phishing"

    # --- Data Breach (VERIS: Hacking + Exfiltrate | DBIR: System Intrusion / Web App) ---
    elif not is_activity and not title_signals_wiper and any(p in text for p in [
        "data breach", "security breach", "source code breach",
        "breached", "breaching systems", "breach of",
        "hack at", "hack of",
        "data theft", "data leak", "data stolen", "stolen data",
        "stolen data records", "stolen records", "stole data",
        "exposed data", "data exposed",
        "unauthorized access to data", "customer data was accessed",
        "records were accessed", "personal information was accessed",
        "sensitive data", "personally identifiable information", "pii",
        "patient data", "medical records exposed",
    ]):
        attack_type = "Data Breach"

    # --- Account Compromise (VERIS: Hacking/stolen creds, Misuse | DBIR: Privilege Misuse) ---
    elif not is_activity and any(p in text for p in [
        "credential theft", "stolen credentials", "credentials stolen",
        "account takeover", "compromised account", "hijacked account",
        "accounts were compromised", "obtained control of credentials",
        "credential stuffing", "password spraying", "brute force",
        "unauthorized login", "fraudulent login",
    ]):
        attack_type = "Account Compromise"

    # --- Activity-only vulnerability classes (CISA advisories / KEV) ---
    # Not shown in the incident feed. Checked here so CISA events are classified
    # correctly before the incident catch-alls below fire.
    elif any(p in text for p in [
        "authentication bypass", "auth bypass", "improper authentication",
        "broken authentication", "bypass authentication",
        "authentication vulnerability", "missing authentication",
    ]):
        attack_type = "Authentication Bypass"
    elif any(p in text for p in [
        "remote code execution", "arbitrary code execution",
        "code execution vulnerability",
    ]):
        attack_type = "Remote Code Execution"
    elif any(p in text for p in [
        "privilege escalation", "elevation of privilege",
        "escalate privileges", "escalating privileges",
        "local privilege escalation",
    ]):
        attack_type = "Privilege Escalation"
    elif any(p in text for p in [
        "sql injection", "command injection", "os command injection",
        "code injection", "injection vulnerability",
        "xpath injection", "ldap injection",
        "cross-site scripting", "xss", "stored xss", "reflected xss",
    ]):
        attack_type = "Injection"

    # --- Malware (VERIS: Malware non-ransomware | DBIR: Crimeware / System Intrusion) ---
    elif not is_activity and not title_signals_breach and any(p in text for p in [
        "malware", "trojan", "infostealer", "backdoor", "loader",
        "spyware", "wiper", "rootkit", "keylogger", "rat ",
        "remote access trojan", "malicious executables",
        "payload", "payloads", "deployed payloads",
        "used to deploy malware", "abused to deploy", "deployed malware",
        "running with system privileges", "disabled antivirus",
        "killing scripts",
        "data-wiping", "data wiping", "wiping attack", "wiper attack",
        "disk wiping", "disk wiper",
    ]):
        attack_type = "Malware"

    # --- Exploitation (VERIS: Hacking | DBIR: Basic Web App / System Intrusion) ---
    # Catches technical vulnerability exploitation AND serves as the catch-all for any
    # confirmed intrusion described with generic language (hacked, cyberattack, etc.)
    # where no more specific type was identified above.
    elif _has_exploitation_signal(text):
        attack_type = "Exploitation"

    # --- Disruption (VERIS: any action | DBIR: Everything Else) ---
    # Availability impact confirmed but no specific mechanism identified. Checked last
    # among incident types so more specific labels (Ransomware, Malware, Exploitation)
    # always win when both mechanism and impact are described.
    elif not is_activity and any(p in text for p in [
        "service disruption", "services disrupted", "systems disrupted",
        "knocked offline", "taken offline", "forced offline",
        "systems offline", "systems down", "services down",
        "operations disrupted", "operations halted", "operations suspended",
        "temporarily offline", "website defaced", "defaced",
        "disrupted operations", "disrupting operations",
    ]):
        attack_type = "Disruption"

    short_event_summary = _build_short_event_summary(article)

    attack_type = normalize_attack_type(attack_type)

    # Geography without a named victim is almost always incidental — body text mentions
    # a US-headquartered company or registry in passing, not as the attack target.
    # Suppress region/country for no-victim campaign articles to avoid false geo attribution.
    if not victim_org_name:
        geography = {"region": None, "country": None, "city": None}

    signals = {
        "victim_org_name": victim_org_name,
        "victim_org_normalized": victim_org_normalized,
        "industry": industry,
        "region": geography["region"],
        "country": geography["country"],
        "city": geography["city"],
        "attack_type": attack_type,
        "event_signal_type": signal_kind or "incident",
        "short_event_summary": short_event_summary,
        "extraction_confidence": None,
    }

    signals["victim_org_normalized"] = _normalize_org_name(
        signals.get("victim_org_name")
    )

    anchor_name, anchor_type = _extract_event_anchor(
        article,
        victim_org_name=signals.get("victim_org_name"),
        actor_name=signals.get("actor_name"),
    )

    # CVE IDs and generic descriptors are not useful display labels.
    signals["victim_display_label"] = (
        None
        if anchor_type == "vulnerability" or _is_generic_org_descriptor(anchor_name or "")
        else anchor_name
    )
    signals["victim_entity_type"] = normalize_event_anchor_type(anchor_type)

    is_cisa_advisory = article.source_name == "cisa-alerts-advisories"
    is_cisa_source = article.source_name in {"cisa-kev", "cisa-alerts-advisories"}
    article_title = (article.title or "").strip()
    clean_substring = bool(
        anchor_name
        and anchor_name != article_title
        and len(anchor_name.split()) <= 6
        and anchor_name[:1].isupper()
    )
    if (not signals.get("victim_org_name")
            and anchor_type == "product_or_platform"
            and anchor_name
            and (is_cisa_source or clean_substring)):
        if is_cisa_advisory:
            vendor = _extract_cisa_vendor(anchor_name)
            if vendor and not _is_generic_org_descriptor(vendor):
                signals["victim_org_name"] = vendor
                signals["victim_org_normalized"] = _normalize_org_name(vendor)
                signals["victim_display_label"] = vendor
        else:
            cleaned_anchor = _clean_org_name(anchor_name)
            if cleaned_anchor and not _is_generic_org_descriptor(cleaned_anchor):
                signals["victim_org_name"] = cleaned_anchor
                signals["victim_org_normalized"] = _normalize_org_name(cleaned_anchor)
                signals["victim_display_label"] = cleaned_anchor
            else:
                signals["victim_display_label"] = None
        if signals.get("industry") in (None, "Unknown"):
            signals["industry"] = "Technology"

    # CISA KEV: anchor is always CVE-YYYY-NNNNN (type=vulnerability), so the
    # product_or_platform block above never fires. Extract vendor for display only.
    # Do NOT set victim_org_name — that would cluster distinct CVEs from the same
    # vendor into one event.
    if article.source_name == "cisa-kev" and not signals.get("victim_display_label"):
        kev_title = (article.title or "").strip()
        if kev_title:
            vendor = _extract_cisa_vendor(kev_title)
            if vendor and not _is_generic_org_descriptor(vendor):
                signals["victim_display_label"] = vendor
                if signals.get("industry") in (None, "Unknown"):
                    signals["industry"] = "Technology"

    return signals


def save_extraction(article_id, signals):
    """
    Save thin MVP extraction signals to the database.
    """
    if not signals.get("victim_org_name"):
        signals["actor_name"] = None
        signals["actor_type"] = None
        signals["attribution_status"] = None

    if not signals.get("actor_name"):
        signals["actor_type"] = None
        signals["attribution_status"] = None
    else:
        if signals.get("attribution_status") == "unknown":
            signals["attribution_status"] = None

    extraction = ArticleExtraction.query.filter_by(raw_article_id=article_id).first()

    if extraction is None:
        extraction = ArticleExtraction(raw_article_id=article_id)
        db.session.add(extraction)

    extraction.victim_org_name = signals.get("victim_org_name")
    extraction.victim_org_normalized = signals.get("victim_org_normalized")
    extraction.victim_display_label = signals.get("victim_display_label")
    extraction.victim_entity_type = signals.get("victim_entity_type")
    extraction.industry = signals.get("industry")
    extraction.region = signals.get("region")
    extraction.country = signals.get("country")
    extraction.city = signals.get("city")
    extraction.attack_type = signals.get("attack_type")
    extraction.short_event_summary = signals.get("short_event_summary")
    extraction.extracted_signals = signals
    extraction.extraction_confidence = signals.get("extraction_confidence")
    extraction.actor_name = signals.get("actor_name")
    extraction.actor_type = signals.get("actor_type")
    extraction.attribution_status = signals.get("attribution_status")

    db.session.commit()
    return extraction


def mark_ready_for_clustering(article):
    """
    Mark article as ready for clustering.
    """
    article.processing_status = "ready_for_clustering"
    db.session.commit()
    return article