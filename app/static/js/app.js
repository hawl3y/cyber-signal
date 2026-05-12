const FILTER_STORAGE_KEY = "cyber_signal_filters_mvp";

function getDefaultFilters() {
    return {
        time_range: "30d",
        signal_type: "",
        industry: "",
        attack_type: "",
    };
}

function getCurrentFilters() {
    const timeRangeEl = document.getElementById("filter-time-range");
    const signalTypeEl = document.getElementById("filter-signal-type");
    const industryEl = document.getElementById("filter-industry");
    const attackTypeEl = document.getElementById("filter-attack-type");

    return {
        time_range: timeRangeEl ? timeRangeEl.value : "30d",
        signal_type: signalTypeEl ? signalTypeEl.value : "",
        industry: industryEl ? industryEl.value : "",
        attack_type: attackTypeEl ? attackTypeEl.value : "",
    };
}

function getSavedFilters() {
    try {
        const raw = window.localStorage.getItem(FILTER_STORAGE_KEY);
        if (!raw) {
            return getDefaultFilters();
        }

        return {
            ...getDefaultFilters(),
            ...JSON.parse(raw),
        };
    } catch (err) {
        console.error("Failed to read saved filters:", err);
        return getDefaultFilters();
    }
}

function saveFilters(filters) {
    try {
        window.localStorage.setItem(FILTER_STORAGE_KEY, JSON.stringify(filters));
    } catch (err) {
        console.error("Failed to save filters:", err);
    }
}

function applyFiltersToControls(filters) {
    const timeRangeEl = document.getElementById("filter-time-range");
    const signalTypeEl = document.getElementById("filter-signal-type");
    const industryEl = document.getElementById("filter-industry");
    const attackTypeEl = document.getElementById("filter-attack-type");

    if (timeRangeEl) {
        timeRangeEl.value = filters.time_range !== undefined ? filters.time_range : "30d";
    }
    if (signalTypeEl) signalTypeEl.value = filters.signal_type || "";
    if (industryEl) industryEl.value = filters.industry || "";
    if (attackTypeEl) attackTypeEl.value = filters.attack_type || "";
}

function buildQueryString(filters) {
    const params = new URLSearchParams();

    Object.entries(filters).forEach(([key, value]) => {
        if (value) {
            params.append(key, value);
        }
    });

    const query = params.toString();
    return query ? `?${query}` : "";
}

function formatMetaLabel(value) {
    if (!value) return "";

    return value
        .toString()
        .split("_")
        .map(part => part.charAt(0).toUpperCase() + part.slice(1))
        .join(" ");
}

function formatSignalTypeLabel(value) {
    if (!value) return "Incident";
    if (value === "activity") return "Activity";
    return "Incident";
}

function scoreBandFor(score) {
    if (score === null || score === undefined) return null;
    if (score >= 75) return "high";
    if (score >= 50) return "med";
    return "low";
}

const SHIELD_SVG = '<svg class="score-icon" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M12 2 4 5v6c0 5 3.4 9.7 8 11 4.6-1.3 8-6 8-11V5l-8-3z"/></svg>';

function buildScoreTooltip(score, factors) {
    const base = `Trust ${score}/100`;
    if (!factors || !factors.length) return base;
    return `${base} — ${factors.join(" · ")}`;
}

const FACET_KEYS = ["signal_type", "industry", "attack_type"];
const FACET_SELECT_IDS = {
    signal_type: "filter-signal-type",
    industry: "filter-industry",
    attack_type: "filter-attack-type",
};
const FACET_CHIP_LABELS = {
    signal_type: "Signal",
    industry: "Industry",
    attack_type: "Threat Type",
};

let cachedTimeRangeEvents = [];
let cachedTimeRange = null;

function eventMatchesFilters(event, filters, exceptFacet) {
    return FACET_KEYS.every(facet => {
        if (facet === exceptFacet) return true;
        const selected = filters[facet];
        if (!selected) return true;
        const eventKey = facet === "signal_type" ? "event_signal_type" : facet;
        return event[eventKey] === selected;
    });
}

function buildCountsForFacet(events, facet, filters) {
    const counts = new Map();
    events.forEach(event => {
        if (!eventMatchesFilters(event, filters, facet)) return;
        const value = event[facet];
        if (value) counts.set(value, (counts.get(value) || 0) + 1);
    });
    return counts;
}

function populateSelectWithCounts(selectId, countsMap, currentValue) {
    const select = document.getElementById(selectId);
    if (!select) return;

    select.innerHTML = '<option value="">All</option>';

    if (currentValue && !countsMap.has(currentValue)) {
        const stale = document.createElement("option");
        stale.value = currentValue;
        stale.textContent = `${currentValue} (0)`;
        select.appendChild(stale);
    }

    const sorted = [...countsMap.entries()].sort((a, b) => a[0].localeCompare(b[0]));
    sorted.forEach(([value, count]) => {
        const option = document.createElement("option");
        option.value = value;
        option.textContent = `${value} (${count})`;
        if (count === 0 && value !== currentValue) {
            option.disabled = true;
        }
        select.appendChild(option);
    });

    select.value = currentValue || "";
}

function recomputeFacetCounts(filters) {
    FACET_KEYS.filter(k => k !== "signal_type").forEach(facet => {
        const counts = buildCountsForFacet(cachedTimeRangeEvents, facet, filters);
        populateSelectWithCounts(FACET_SELECT_IDS[facet], counts, filters[facet] || "");
    });
}

async function loadFilterOptions(filters) {
    try {
        if (filters.time_range !== cachedTimeRange) {
            const params = new URLSearchParams();
            if (filters.time_range) params.append("time_range", filters.time_range);
            params.append("limit", "500");
            const response = await fetch(`/api/events/?${params}`);
            cachedTimeRangeEvents = await response.json();
            cachedTimeRange = filters.time_range;
        }
        recomputeFacetCounts(filters);
    } catch (err) {
        console.error("Failed to load filter options:", err);
    }
}

function renderFilterChips(filters) {
    const container = document.getElementById("filter-chips");
    if (!container) return;

    container.innerHTML = "";
    const active = FACET_KEYS.filter(key => filters[key]);

    if (!active.length) {
        container.classList.remove("has-chips");
        return;
    }

    active.forEach(key => {
        const chip = document.createElement("button");
        chip.type = "button";
        chip.className = "filter-chip";
        chip.setAttribute("aria-label", `Clear ${FACET_CHIP_LABELS[key]} filter`);
        chip.innerHTML = `
            <span class="filter-chip-label">${FACET_CHIP_LABELS[key]}: ${formatMetaLabel(filters[key])}</span>
            <span class="filter-chip-x" aria-hidden="true">×</span>
        `;
        chip.addEventListener("click", () => clearOneFilter(key));
        container.appendChild(chip);
    });

    container.classList.add("has-chips");
}

async function clearOneFilter(key) {
    const select = document.getElementById(FACET_SELECT_IDS[key]);
    if (select) select.value = "";
    await handleFilterChange();
}

async function loadSummary() {
    try {
        const query = buildQueryString(getCurrentFilters());
        const response = await fetch(`/api/summary/${query}`);
        const data = await response.json();

        const totalEl = document.getElementById("total-events");
        const highTrustEl = document.getElementById("high-trust-events");
        const highImpactEl = document.getElementById("high-impact-events");
        const newTodayEl = document.getElementById("new-today-events");

        if (totalEl) totalEl.textContent = data.total_events ?? "--";
        if (highTrustEl) highTrustEl.textContent = data.high_trust_events ?? "--";
        if (highImpactEl) highImpactEl.textContent = data.high_impact_events ?? "--";
        if (newTodayEl) newTodayEl.textContent = data.new_today_events ?? "--";
    } catch (err) {
        console.error("Failed to load summary:", err);
    }
}

function renderEmptyTrend(container, message) {
    container.innerHTML = `<p class='placeholder-text'>${message}</p>`;
}

function renderRisingTrend(items) {
    const container = document.getElementById("trend-rising");
    if (!container) return;
    container.innerHTML = "";

    if (!items || !items.length) {
        renderEmptyTrend(container, "No activity in the last 7 days.");
        return;
    }

    items.forEach(item => {
        const row = document.createElement("div");
        row.className = "trend-row";
        const indicator = trendDeltaIndicator(item);
        row.innerHTML = `
            <span class="trend-label">${item.label}</span>
            <span class="trend-delta ${indicator.className}" title="${indicator.title}">${indicator.text}</span>
        `;
        container.appendChild(row);
    });
}

function trendDeltaIndicator(item) {
    if (item.is_new && item.current > 0) {
        return {
            text: "NEW",
            className: "trend-delta-new",
            title: `${item.current} this week, none in the prior 7 days`,
        };
    }
    if (item.delta > 0) {
        return {
            text: `+${item.delta}`,
            className: "trend-delta-up",
            title: `${item.current} this week vs ${item.previous} prior 7d`,
        };
    }
    if (item.delta < 0) {
        return {
            text: `${item.delta}`,
            className: "trend-delta-down",
            title: `${item.current} this week vs ${item.previous} prior 7d`,
        };
    }
    return {
        text: `${item.current}`,
        className: "trend-delta-flat",
        title: `${item.current} this week, unchanged from prior 7d`,
    };
}

function renderCountTrend(containerId, items, emptyMessage, suffix) {
    const container = document.getElementById(containerId);
    if (!container) return;
    container.innerHTML = "";

    if (!items || !items.length) {
        renderEmptyTrend(container, emptyMessage);
        return;
    }

    items.forEach(item => {
        const row = document.createElement("div");
        row.className = "trend-row";
        const label = (suffix && item.count === 1) ? suffix.singular : (suffix && suffix.plural);
        const countText = label ? `${item.count} ${label}` : `${item.count}`;
        row.innerHTML = `
            <span class="trend-label">${item.label}</span>
            <span class="trend-count">${countText}</span>
        `;
        container.appendChild(row);
    });
}

async function loadTrends() {
    try {
        const query = buildQueryString(getCurrentFilters());
        const response = await fetch(`/api/summary/trends${query}`);
        const data = await response.json();

        renderRisingTrend(data.rising_attack_types || []);
        renderCountTrend(
            "trend-active-actors",
            data.active_actors || [],
            "No attributed actors in the last 7 days.",
            { singular: "event", plural: "events" }
        );
        renderCountTrend(
            "trend-sources",
            data.top_sources || [],
            "No coverage data.",
            { singular: "event", plural: "events" }
        );
    } catch (err) {
        console.error("Failed to load trends:", err);
    }
}

function buildEventMeta(event) {
    return {
        primary: [
            event.display_entity ? { value: event.display_entity } : null,
            event.attack_type ? { value: event.attack_type } : null,
            event.display_location ? { value: event.display_location } : null,
            event.display_attribution ? { value: event.display_attribution } : null,
        ].filter(Boolean),
        secondary: [
            formatMetaLabel(event.status),
            formatMetaLabel(event.confidence),
            event.time,
        ].filter(Boolean),
    };
}

function escapeHtml(value) {
    if (value === null || value === undefined) return "";
    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

function formatSourceDate(value) {
    if (!value) return "";
    const d = new Date(value);
    if (!Number.isFinite(d.getTime())) return "";
    return d.toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric" });
}

function renderScoreFactors(factors) {
    if (!factors || !factors.length) return "";
    const chips = factors
        .map(f => `<span class="factor-chip">${escapeHtml(f)}</span>`)
        .join("");
    return `
        <div class="event-detail-section">
            <h4>Score factors</h4>
            <div class="factor-row">${chips}</div>
        </div>
    `;
}

function renderSourceList(sources) {
    if (!sources || !sources.length) return "";
    const items = sources.map(s => {
        const url = s.url ? escapeHtml(s.url) : "";
        const publisher = escapeHtml(s.publisher || s.source_name || "");
        const title = escapeHtml(s.title || "(untitled)");
        const date = formatSourceDate(s.published_at);
        const primaryBadge = s.is_primary_source
            ? '<span class="source-badge">primary</span>'
            : "";
        const link = url
            ? `<a href="${url}" target="_blank" rel="noopener noreferrer">${title}</a>`
            : title;
        return `
            <li class="source-row">
                <span class="source-publisher">${publisher}${primaryBadge}</span>
                <span class="source-title">${link}</span>
                ${date ? `<span class="source-date">${date}</span>` : ""}
            </li>
        `;
    }).join("");
    return `
        <div class="event-detail-section">
            <h4>Sources</h4>
            <ul class="source-list">${items}</ul>
        </div>
    `;
}

function renderCveLink(cveId) {
    if (!cveId) return "";
    const safe = escapeHtml(cveId);
    const url = `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cveId)}`;
    return `
        <div class="event-detail-section">
            <h4>Related</h4>
            <a class="cve-link" href="${url}" target="_blank" rel="noopener noreferrer">${safe}</a>
        </div>
    `;
}

function renderDetailMeta(event) {
    const meta = buildEventMeta(event);
    const text = meta.secondary.join(" · ");
    if (!text) return "";
    return `<div class="event-detail-meta">${escapeHtml(text)}</div>`;
}

function renderEventCard(event) {
    const el = document.createElement("article");
    const scoreBand = scoreBandFor(event.confidence_score);
    el.className = `event-card score-${scoreBand || "low"}`;

    const highTrust = typeof event.confidence_score === "number" && event.confidence_score >= 80;
    if (event.actor_name || highTrust) {
        el.classList.add("high-signal");
    }

    const meta = buildEventMeta(event);

    const primaryPills = meta.primary
        .map(item => `<span class="meta-pill ${item.className || ""}">${formatMetaLabel(item.value)}</span>`)
        .join("");

    const signalTypePill = `
        <span class="signal-pill signal-${event.event_signal_type || "incident"}">
            ${formatSignalTypeLabel(event.event_signal_type)}
        </span>
    `;

    const tooltip = buildScoreTooltip(event.confidence_score, event.score_factors);
    const scorePill = scoreBand
        ? `<span class="score-pill score-${scoreBand}" title="${escapeHtml(tooltip)}">${SHIELD_SVG}${event.confidence_score}</span>`
        : "";

    const metaRow = primaryPills ? `<div class="event-meta">${primaryPills}</div>` : "";
    const time = event.time ? `<span class="event-time-inline">${escapeHtml(event.time)}</span>` : "";

    const detail = `
        <div class="event-detail">
            <p class="event-summary-full">${escapeHtml(event.summary || "No summary available.")}</p>
            ${renderScoreFactors(event.score_factors)}
            ${renderSourceList(event.sources)}
            ${renderCveLink(event.primary_cve_id)}
            ${renderDetailMeta(event)}
        </div>
    `;

    el.innerHTML = `
        <div class="event-card-header">
            <h3>${escapeHtml(event.title || "Untitled Event")}</h3>
            <div class="event-card-header-pills">
                ${scorePill}
                ${signalTypePill}
            </div>
        </div>
        <p class="event-summary-preview">${escapeHtml(event.summary || "")}</p>
        ${metaRow}
        ${time}
        ${detail}
    `;

    el.addEventListener("click", (ev) => {
        if (ev.target.closest("a")) return;
        el.classList.toggle("expanded");
    });

    return el;
}

let activeCardFilter = null;

function applyCardFilter(events) {
    if (!activeCardFilter || activeCardFilter === "total") return events;
    if (activeCardFilter === "high_trust") {
        return events.filter(e => typeof e.confidence_score === "number" && e.confidence_score >= 75);
    }
    if (activeCardFilter === "high_impact") {
        return events.filter(e => e.high_impact);
    }
    if (activeCardFilter === "new") {
        const cutoff = Date.now() - 24 * 60 * 60 * 1000;
        return events.filter(e => {
            if (!e.published_at) return false;
            const t = new Date(e.published_at).getTime();
            return Number.isFinite(t) && t >= cutoff;
        });
    }
    return events;
}

function updateCardActiveStates() {
    document.querySelectorAll(".summary-card").forEach(card => {
        const key = card.getAttribute("data-card-filter");
        const isActive = activeCardFilter && activeCardFilter !== "total" && key === activeCardFilter;
        card.classList.toggle("active", Boolean(isActive));
    });
}

async function loadEvents() {
    try {
        const query = buildQueryString(getCurrentFilters());
        const response = await fetch(`/api/events/${query}`);
        const allEvents = await response.json();
        const events = applyCardFilter(allEvents);

        const container = document.getElementById("event-feed");
        const countEl = document.getElementById("feed-count");

        if (!container) return;
        container.innerHTML = "";

        if (countEl) {
            const totalNote = activeCardFilter && activeCardFilter !== "total"
                ? ` of ${allEvents.length}`
                : "";
            countEl.textContent = `${events.length} event${events.length === 1 ? "" : "s"}${totalNote}`;
        }

        if (!events.length) {
            container.innerHTML = "<p class='placeholder-text'>No events found.</p>";
            return;
        }

        events.forEach(event => {
            const el = renderEventCard(event);
            container.appendChild(el);
        });
    } catch (err) {
        console.error("Failed to load events:", err);
    }
}

function setLoading(isLoading) {
    [
        document.getElementById("event-feed"),
        document.getElementById("trend-attack-types"),
        document.getElementById("trend-industries"),
    ].forEach(section => {
        if (!section) return;

        if (isLoading) {
            section.classList.add("loading");
        } else {
            section.classList.remove("loading");
        }
    });
}

async function refreshDashboard() {
    await loadSummary();
    await loadEvents();
    await loadTrends();
}

async function handleFilterChange() {
    setLoading(true);

    try {
        const filters = getCurrentFilters();
        saveFilters(filters);
        await loadFilterOptions(filters);
        applyFiltersToControls(filters);
        renderFilterChips(filters);
        await refreshDashboard();
    } finally {
        setLoading(false);
    }
}

async function resetFilters() {
    setLoading(true);

    try {
        const defaults = getDefaultFilters();
        saveFilters(defaults);
        activeCardFilter = null;
        await loadFilterOptions(defaults);
        applyFiltersToControls(defaults);
        renderFilterChips(defaults);
        updateCardActiveStates();
        await refreshDashboard();
    } finally {
        setLoading(false);
    }
}

[
    "filter-time-range",
    "filter-signal-type",
    "filter-industry",
    "filter-attack-type",
].forEach(id => {
    const el = document.getElementById(id);
    if (el) {
        el.addEventListener("change", handleFilterChange);
    }
});

const resetButton = document.getElementById("reset-filters");
if (resetButton) {
    resetButton.addEventListener("click", resetFilters);
}

async function handleCardClick(cardFilter) {
    if (cardFilter === "total") {
        activeCardFilter = null;
        const filters = { ...getDefaultFilters(), time_range: getCurrentFilters().time_range };
        saveFilters(filters);
        await loadFilterOptions(filters);
        applyFiltersToControls(filters);
        renderFilterChips(filters);
        updateCardActiveStates();
        await refreshDashboard();
        return;
    }

    activeCardFilter = activeCardFilter === cardFilter ? null : cardFilter;
    updateCardActiveStates();
    await loadEvents();
}

document.querySelectorAll(".summary-card[data-card-filter]").forEach(card => {
    card.addEventListener("click", () => {
        const key = card.getAttribute("data-card-filter");
        handleCardClick(key);
    });
});

const toggleFiltersBtn = document.getElementById("toggle-filters");
const filtersPanel = document.querySelector(".filters-panel");

function updateFilterToggleLabel() {
    if (!toggleFiltersBtn || !filtersPanel) return;

    if (filtersPanel.classList.contains("expanded")) {
        toggleFiltersBtn.textContent = "Hide Filters";
    } else {
        toggleFiltersBtn.textContent = "Show Filters";
    }
}

if (toggleFiltersBtn && filtersPanel) {
    toggleFiltersBtn.addEventListener("click", () => {
        filtersPanel.classList.toggle("expanded");
        updateFilterToggleLabel();
    });

    // Default: collapsed on mobile, expanded on desktop
    if (window.innerWidth > 640) {
        filtersPanel.classList.add("expanded");
    } else {
        filtersPanel.classList.remove("expanded");
    }

    updateFilterToggleLabel();
}

function formatEasternTimestamp(value) {
    const date = value ? new Date(value) : new Date();

    return new Intl.DateTimeFormat("en-US", {
        weekday: "short",
        month: "short",
        day: "numeric",
        hour: "numeric",
        minute: "2-digit",
        timeZone: "America/New_York",
        timeZoneName: "short",
    }).format(date);
}

function setFooterStatusText(timestamp) {
    const yearEl = document.getElementById("footer-year");
    const updatedEl = document.getElementById("footer-updated");

    if (yearEl) {
        yearEl.textContent = new Date().getFullYear();
    }

    if (updatedEl) {
        updatedEl.textContent = formatEasternTimestamp(timestamp);
    }
}

async function loadFooterStatus() {
    try {
        const response = await fetch("/api/automation/status");
        const data = await response.json();

        if (data.last_data_updated_at) {
            setFooterStatusText(data.last_data_updated_at);
        }
    } catch (err) {
        console.error("Failed to load footer status:", err);
    }
}

setLoading(true);

(async () => {
    try {
        const initialFilters = getSavedFilters();
        await loadFilterOptions(initialFilters);
        applyFiltersToControls(initialFilters);
        renderFilterChips(initialFilters);
        await refreshDashboard();
        await loadFooterStatus();
    } finally {
        setLoading(false);
    }
})();