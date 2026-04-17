const FILTER_STORAGE_KEY = "cyber_signal_filters_mvp";

function getDefaultFilters() {
    return {
        time_range: "7d",
        industry: "",
        region: "",
        attack_type: "",
    };
}

function getCurrentFilters() {
    return {
        time_range: document.getElementById("filter-time-range")?.value || "7d",
        industry: document.getElementById("filter-industry")?.value || "",
        region: document.getElementById("filter-region")?.value || "",
        attack_type: document.getElementById("filter-attack-type")?.value || "",
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

    if (timeRangeEl) timeRangeEl.value = filters.time_range || "7d";
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

function populateSelect(selectId, values) {
    const select = document.getElementById(selectId);
    if (!select) return;

    const currentValue = select.value || "";
    select.innerHTML = '<option value="">All</option>';

    values.forEach(value => {
        const option = document.createElement("option");
        option.value = value;
        option.textContent = value;
        select.appendChild(option);
    });

    if ([...select.options].some(option => option.value === currentValue)) {
        select.value = currentValue;
    }
}

function getUniqueValues(events, key) {
    return [...new Set(events.map(event => event[key]).filter(Boolean))].sort();
}

async function loadFilterOptions() {
    try {
        const response = await fetch("/api/events/?limit=200");
        const events = await response.json();

        populateSelect("filter-industry", getUniqueValues(events, "industry"));
        populateSelect("filter-region", getUniqueValues(events, "region"));
        populateSelect("filter-attack-type", getUniqueValues(events, "attack_type"));

        applyFiltersToControls(getSavedFilters());
    } catch (err) {
        console.error("Failed to load filter options:", err);
    }
}

async function loadSummary() {
    try {
        const query = buildQueryString(getCurrentFilters());
        const response = await fetch(`/api/summary/${query}`);
        const data = await response.json();

        const totalEl = document.getElementById("total-incidents");
        const confirmedEl = document.getElementById("confirmed-incidents");
        const emergingEl = document.getElementById("emerging-signals");
        const attackEl = document.getElementById("top-attack-type");
        const industryEl = document.getElementById("top-targeted-industry");

        if (totalEl) totalEl.textContent = data.total_incidents ?? "--";
        if (confirmedEl) confirmedEl.textContent = data.confirmed_incidents ?? "--";
        if (emergingEl) emergingEl.textContent = data.emerging_signals ?? "--";
        if (attackEl) attackEl.textContent = data.top_attack_type || "—";
        if (industryEl) industryEl.textContent = data.top_targeted_industry || "—";
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
        const response = await fetch("/api/summary/trends");
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
            event.victim_name,
            event.attack_type,
            event.country || event.region,
        ].filter(Boolean),
        secondary: [
            formatMetaLabel(event.status),
            formatMetaLabel(event.confidence),
            event.time,
            `${event.source_count ?? 0} source${(event.source_count ?? 0) === 1 ? "" : "s"}`,
        ].filter(Boolean),
    };
}

async function loadEvents() {
    try {
        const query = buildQueryString(getCurrentFilters());
        const response = await fetch(`/api/events/${query}`);
        const events = await response.json();

        const container = document.getElementById("event-feed");
        const countEl = document.getElementById("feed-count");

        if (!container) return;
        container.innerHTML = "";

        if (countEl) {
            countEl.textContent = `${events.length} incident${events.length === 1 ? "" : "s"}`;
        }

        if (!events.length) {
            container.innerHTML = "<p class='placeholder-text'>No incidents found.</p>";
            return;
        }

        events.forEach(event => {
            const el = document.createElement("article");
            el.className = `event-card status-${event.status || "unknown"}`;

            const meta = buildEventMeta(event);

            const primaryPills = meta.primary
                .map(value => `<span class="meta-pill">${formatMetaLabel(value)}</span>`)
                .join("");

            const secondaryLine = meta.secondary.join(" • ");

            el.innerHTML = `
                <h3>${event.title || "Untitled Event"}</h3>
                <p class="event-summary">${event.summary || "No summary available."}</p>
                <div class="event-meta">${primaryPills}</div>
                <div class="event-subline">${secondaryLine}</div>
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
        applyFiltersToControls(defaults);
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

setLoading(true);

loadFilterOptions()
    .then(refreshDashboard)
    .finally(() => {
        setLoading(false);
    });