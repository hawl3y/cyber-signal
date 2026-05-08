const FILTER_STORAGE_KEY = "cyber_signal_filters_mvp";

function getDefaultFilters() {
    return {
        time_range: "30d",
        industry: "",
        region: "",
        attack_type: "",
    };
}

function getCurrentFilters() {
    const timeRangeEl = document.getElementById("filter-time-range");
    const industryEl = document.getElementById("filter-industry");
    const regionEl = document.getElementById("filter-region");
    const attackTypeEl = document.getElementById("filter-attack-type");

    return {
        time_range: timeRangeEl ? timeRangeEl.value : "30d",
        industry: industryEl ? industryEl.value : "",
        region: regionEl ? regionEl.value : "",
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
    const industryEl = document.getElementById("filter-industry");
    const regionEl = document.getElementById("filter-region");
    const attackTypeEl = document.getElementById("filter-attack-type");

    if (timeRangeEl) {
        timeRangeEl.value = filters.time_range !== undefined ? filters.time_range : "30d";
    }
    if (industryEl) industryEl.value = filters.industry || "";
    if (regionEl) regionEl.value = filters.region || "";
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

const FACET_KEYS = ["industry", "region", "attack_type"];
const FACET_SELECT_IDS = {
    industry: "filter-industry",
    region: "filter-region",
    attack_type: "filter-attack-type",
};
const FACET_CHIP_LABELS = {
    industry: "Industry",
    region: "Region",
    attack_type: "Attack",
};

let cachedTimeRangeEvents = [];
let cachedTimeRange = null;

function eventMatchesFilters(event, filters, exceptFacet) {
    return FACET_KEYS.every(facet => {
        if (facet === exceptFacet) return true;
        const selected = filters[facet];
        if (!selected) return true;
        return event[facet] === selected;
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
    FACET_KEYS.forEach(facet => {
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
            <span class="filter-chip-label">${FACET_CHIP_LABELS[key]}: ${filters[key]}</span>
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

function renderTrendList(containerId, items) {
    const container = document.getElementById(containerId);
    if (!container) return;

    container.innerHTML = "";

    if (!items || !items.length) {
        container.innerHTML = "<p class='placeholder-text'>No trend data available.</p>";
        return;
    }

    items.forEach(item => {
        const row = document.createElement("div");
        row.className = "trend-row";
        row.innerHTML = `
            <span class="trend-label">${item.label}</span>
            <span class="trend-count">${item.count}</span>
        `;
        container.appendChild(row);
    });
}

async function loadTrends() {
    try {
        const query = buildQueryString(getCurrentFilters());
        const response = await fetch(`/api/summary/trends${query}`);
        const data = await response.json();

        renderTrendList("trend-attack-types", data.top_attack_types || []);
        renderTrendList("trend-industries", data.top_industries || []);
    } catch (err) {
        console.error("Failed to load trends:", err);
    }
}

function buildEventMeta(event) {
    return {
        primary: [
            event.display_entity ? { value: event.display_entity } : null,
            event.display_context ? { value: event.display_context } : null,
            event.attack_type ? { value: event.attack_type } : null,
            event.display_location ? { value: event.display_location } : null,
            event.display_attribution ? { value: event.display_attribution, className: "actor-pill" } : null,
        ].filter(Boolean),
        secondary: [
            event.entity_type ? formatMetaLabel(event.entity_type) : null,
            formatMetaLabel(event.status),
            formatMetaLabel(event.confidence),
            event.time,
        ].filter(Boolean),
    };
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
                ? `<span class="score-pill score-${scoreBand}" title="${tooltip}">${SHIELD_SVG}${event.confidence_score}</span>`
                : "";

            const secondaryLine = meta.secondary.join(" • ");
            const metaRow = primaryPills ? `<div class="event-meta">${primaryPills}</div>` : "";
            const sublineRow = secondaryLine ? `<div class="event-subline">${secondaryLine}</div>` : "";

            el.innerHTML = `
                <div class="event-card-header">
                    <h3>${event.title || "Untitled Event"}</h3>
                    <div class="event-card-header-pills">
                        ${scorePill}
                        ${signalTypePill}
                    </div>
                </div>
                <p class="event-summary">${event.summary || "No summary available."}</p>
                ${metaRow}
                ${sublineRow}
            `;

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
    "filter-industry",
    "filter-region",
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