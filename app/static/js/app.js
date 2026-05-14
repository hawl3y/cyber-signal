const FILTER_STORAGE_KEY = "cyber_signal_filters_mvp";
const PAGE_SIZE = 25;

let currentOffset = 0;
let hasMoreEvents = false;
let allLoadedRawEvents = [];

function getDefaultFilters() {
    return {
        time_range: "7d",
        signal_type: "incident",
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
    if (value === "activity") return "Activity";
    if (value === "intelligence") return "Intelligence";
    return "Incident";
}

function formatSignalTypeLabelPlural(value) {
    if (value === "activity") return "Activity";
    if (value === "intelligence") return "Intelligence";
    if (value === "incident") return "Incidents";
    return "All Events";
}

function scoreBandFor(score) {
    if (score === null || score === undefined) return null;
    if (score >= 75) return "high";
    if (score >= 50) return "med";
    return "low";
}

function scoreLabelFor(score) {
    if (score === null || score === undefined) return "";
    if (score >= 75) return "High Trust";
    if (score >= 50) return "Medium";
    return "Low";
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
    industry: "Sector",
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

// ── Context labels ─────────────────────────────────────────

function buildContextText(filters) {
    const signal = formatSignalTypeLabelPlural(filters.signal_type);
    const time = filters.time_range || "All time";
    return `${signal} · ${time}`;
}

function updateContextLabels(filters) {
    const contextText = buildContextText(filters);

    const filterLabel = document.getElementById("filter-context-label");
    if (filterLabel) filterLabel.textContent = contextText;

    const stickyView = document.getElementById("sticky-context-view");
    if (stickyView) stickyView.textContent = contextText;

    const feedLabel = document.getElementById("feed-view-label");
    if (feedLabel) {
        const facets = [];
        if (filters.attack_type) facets.push(filters.attack_type);
        if (filters.industry) facets.push(filters.industry);
        feedLabel.textContent = facets.length
            ? facets.join(" · ")
            : formatSignalTypeLabelPlural(filters.signal_type);
    }
}

// ── Summary loading ────────────────────────────────────────

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

// ── Trend rendering ────────────────────────────────────────

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

// ── Event card rendering ───────────────────────────────────

function buildEventMeta(event) {
    return {
        primary: [
            event.display_entity ? { value: event.display_entity, className: "" } : null,
            event.attack_type    ? { value: event.attack_type, className: "meta-pill-attack" } : null,
            event.display_location ? { value: event.display_location, className: "" } : null,
            event.display_attribution ? { value: event.display_attribution, className: "meta-pill-actor" } : null,
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
    const scoreLabel = scoreLabelFor(event.confidence_score);
    const scorePill = scoreBand
        ? `<span class="score-pill score-${scoreBand}" title="${escapeHtml(tooltip)}">${SHIELD_SVG}${escapeHtml(scoreLabel)}</span>`
        : "";

    const impactBadge = event.high_impact
        ? `<span class="high-impact-badge">High Impact</span>`
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
                ${impactBadge}
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

// ── Skeleton loading ───────────────────────────────────────

function showSkeleton(container, count = 4) {
    if (!container) return;
    container.innerHTML = Array.from({ length: count }, () => `
        <div class="skeleton-card">
            <div class="skeleton-line skeleton-title"></div>
            <div class="skeleton-line skeleton-body"></div>
            <div class="skeleton-line skeleton-body-short"></div>
            <div class="skeleton-pills">
                <div class="skeleton-line skeleton-pill" style="width:80px"></div>
                <div class="skeleton-line skeleton-pill" style="width:90px"></div>
                <div class="skeleton-line skeleton-pill" style="width:70px"></div>
            </div>
        </div>
    `).join("");
}

// ── Card filter / feed count ───────────────────────────────

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

function updateLoadMoreButton() {
    const btn = document.getElementById("load-more-btn");
    if (!btn) return;
    btn.style.display = hasMoreEvents ? "block" : "none";
}

function updateFeedCount() {
    const countEl = document.getElementById("feed-count");
    const displayed = applyCardFilter(allLoadedRawEvents);
    const totalNote = activeCardFilter && activeCardFilter !== "total"
        ? ` of ${allLoadedRawEvents.length} loaded`
        : "";
    const countText = `${displayed.length} event${displayed.length === 1 ? "" : "s"}${totalNote}`;

    if (countEl) countEl.textContent = countText;

    const stickyCount = document.getElementById("sticky-context-count");
    if (stickyCount) stickyCount.textContent = countText;
}

// ── Event loading ──────────────────────────────────────────

function buildEmptyStateMessage(filters) {
    const parts = [];
    if (filters.signal_type) parts.push(formatSignalTypeLabelPlural(filters.signal_type).toLowerCase());
    if (filters.attack_type) parts.push(filters.attack_type.toLowerCase());
    if (filters.industry) parts.push(filters.industry.toLowerCase());
    const what = parts.length ? parts.join(" · ") : "events";
    const when = filters.time_range ? `the last ${filters.time_range}` : "all time";
    return `No ${what} found in ${when}. Try adjusting the filters.`;
}

async function loadEvents() {
    currentOffset = 0;
    hasMoreEvents = false;
    allLoadedRawEvents = [];

    const container = document.getElementById("event-feed");
    if (!container) return;

    showSkeleton(container);

    try {
        const filters = getCurrentFilters();
        const params = new URLSearchParams();
        Object.entries(filters).forEach(([k, v]) => { if (v) params.append(k, v); });
        params.append("limit", PAGE_SIZE);

        const response = await fetch(`/api/events/?${params}`);
        const newEvents = await response.json();

        hasMoreEvents = newEvents.length === PAGE_SIZE;
        currentOffset = newEvents.length;
        allLoadedRawEvents = newEvents;

        const displayed = applyCardFilter(allLoadedRawEvents);
        container.innerHTML = "";
        updateFeedCount();

        if (!displayed.length) {
            container.innerHTML = `<p class='placeholder-text'>${buildEmptyStateMessage(filters)}</p>`;
        } else {
            displayed.forEach(event => container.appendChild(renderEventCard(event)));
        }

        updateLoadMoreButton();
    } catch (err) {
        console.error("Failed to load events:", err);
        container.innerHTML = "<p class='placeholder-text'>Failed to load events. Please try again.</p>";
    }
}

async function loadMoreEvents() {
    if (!hasMoreEvents) return;

    const container = document.getElementById("event-feed");
    if (!container) return;

    const btn = document.getElementById("load-more-btn");
    if (btn) btn.disabled = true;

    try {
        const filters = getCurrentFilters();
        const params = new URLSearchParams();
        Object.entries(filters).forEach(([k, v]) => { if (v) params.append(k, v); });
        params.append("limit", PAGE_SIZE);
        params.append("offset", currentOffset);

        const response = await fetch(`/api/events/?${params}`);
        const newEvents = await response.json();

        hasMoreEvents = newEvents.length === PAGE_SIZE;
        currentOffset += newEvents.length;
        allLoadedRawEvents = [...allLoadedRawEvents, ...newEvents];

        const filteredNew = applyCardFilter(newEvents);
        filteredNew.forEach(event => container.appendChild(renderEventCard(event)));
        updateFeedCount();
        updateLoadMoreButton();
    } catch (err) {
        console.error("Failed to load more events:", err);
    } finally {
        if (btn) btn.disabled = false;
    }
}

function setLoading(isLoading) {
    [
        document.getElementById("trend-rising"),
        document.getElementById("trend-active-actors"),
        document.getElementById("trend-sources"),
    ].forEach(section => {
        if (!section) return;
        section.classList.toggle("loading", isLoading);
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
        updateContextLabels(filters);
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
        updateContextLabels(defaults);
        await loadFilterOptions(defaults);
        applyFiltersToControls(defaults);
        renderFilterChips(defaults);
        updateCardActiveStates();
        await refreshDashboard();
    } finally {
        setLoading(false);
    }
}

// ── Filter controls wiring ─────────────────────────────────

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

const loadMoreBtn = document.getElementById("load-more-btn");
if (loadMoreBtn) {
    loadMoreBtn.addEventListener("click", loadMoreEvents);
}

async function handleCardClick(cardFilter) {
    if (cardFilter === "total") {
        activeCardFilter = null;
        const filters = { ...getDefaultFilters(), time_range: getCurrentFilters().time_range };
        saveFilters(filters);
        updateContextLabels(filters);
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

// ── Filter toggle ──────────────────────────────────────────

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

// ── Trends panel toggle (mobile) ───────────────────────────

const trendsPanel = document.getElementById("trends-panel");
const trendsHeader = document.getElementById("trends-header");

if (trendsPanel && trendsHeader) {
    trendsHeader.addEventListener("click", () => {
        if (window.innerWidth > 640) return;
        const expanded = trendsPanel.classList.toggle("expanded");
        trendsHeader.setAttribute("aria-expanded", String(expanded));
    });

    trendsHeader.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            trendsHeader.click();
        }
    });
}

// ── Sticky context bar ─────────────────────────────────────

const stickyBar = document.getElementById("sticky-context-bar");
const summaryStrip = document.querySelector(".summary-strip");

if (stickyBar && summaryStrip && typeof IntersectionObserver !== "undefined") {
    const observer = new IntersectionObserver(
        ([entry]) => {
            const shouldShow = !entry.isIntersecting;
            stickyBar.classList.toggle("visible", shouldShow);
            stickyBar.setAttribute("aria-hidden", String(!shouldShow));
        },
        { threshold: 0 }
    );
    observer.observe(summaryStrip);
}

// ── Footer ─────────────────────────────────────────────────

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

// ── Init ───────────────────────────────────────────────────

setLoading(true);

(async () => {
    try {
        const initialFilters = getSavedFilters();
        updateContextLabels(initialFilters);
        await loadFilterOptions(initialFilters);
        applyFiltersToControls(initialFilters);
        renderFilterChips(initialFilters);
        await refreshDashboard();
        await loadFooterStatus();
    } finally {
        setLoading(false);
    }
})();
