const FILTER_STORAGE_KEY = "cyber_signal_filters";
const EVENTS_PAGE_SIZE = 25;
const WORLD_GEOJSON_URL = "/static/data/world-countries.geo.json";
let currentPage = 1;
let lastLoadedEventCount = 0;
let worldGeoJsonPromise = null;

function formatLabel(value) {
    if (!value) return "—";

    return value
        .toString()
        .split("_")
        .map(part => part.charAt(0).toUpperCase() + part.slice(1))
        .join(" ");
}

function getDefaultFilters() {
    return {
        industry: "",
        region: "",
        country: "",
        attack_type: "",
        start_date: "",
        end_date: "",
    };
}

function getCurrentFilters() {
    return {
        industry: document.getElementById("filter-industry")?.value || "",
        region: document.getElementById("filter-region")?.value || "",
        country: document.getElementById("filter-country")?.value || "",
        attack_type: document.getElementById("filter-attack-type")?.value || "",
        start_date: document.getElementById("filter-start-date")?.value || "",
        end_date: document.getElementById("filter-end-date")?.value || "",
    };
}

function getSavedFilters() {
    try {
        const raw = window.localStorage.getItem(FILTER_STORAGE_KEY);

        if (!raw) {
            return getDefaultFilters();
        }

        const parsed = JSON.parse(raw);

        return {
            ...getDefaultFilters(),
            ...parsed,
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
    const industryEl = document.getElementById("filter-industry");
    const regionEl = document.getElementById("filter-region");
    const countryEl = document.getElementById("filter-country");
    const attackTypeEl = document.getElementById("filter-attack-type");
    const startDateEl = document.getElementById("filter-start-date");
    const endDateEl = document.getElementById("filter-end-date");

    if (industryEl) industryEl.value = filters.industry || "";
    if (regionEl) regionEl.value = filters.region || "";
    if (countryEl) countryEl.value = filters.country || "";
    if (attackTypeEl) attackTypeEl.value = filters.attack_type || "";
    if (startDateEl) startDateEl.value = filters.start_date || "";
    if (endDateEl) endDateEl.value = filters.end_date || "";
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

function buildEventsQuery(filters, page = 1) {
    return buildQueryString({
        ...filters,
        limit: EVENTS_PAGE_SIZE,
        offset: Math.max(0, (page - 1) * EVENTS_PAGE_SIZE),
    });
}

async function loadWorldGeoJson() {
    if (worldGeoJsonPromise) {
        return worldGeoJsonPromise;
    }

    worldGeoJsonPromise = fetch(WORLD_GEOJSON_URL)
        .then(response => {
            if (!response.ok) {
                throw new Error("Failed to load world GeoJSON.");
            }
            return response.json();
        });

    return worldGeoJsonPromise;
}

function populateSelect(selectId, values) {
    const select = document.getElementById(selectId);
    if (!select) {
        return;
    }

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

async function loadFilters() {
    try {
        const savedFilters = getSavedFilters();
        const query = buildQueryString(savedFilters);

        const response = await fetch(`/api/filters/${query}`);
        const data = await response.json();

        populateSelect("filter-industry", data.industries || []);
        populateSelect("filter-region", data.regions || []);
        populateSelect("filter-country", data.countries || []);
        populateSelect("filter-attack-type", data.attack_types || []);

        applyFiltersToControls(savedFilters);
    } catch (err) {
        console.error("Failed to load filters:", err);
    }
}

async function loadSummary() {
    try {
        const query = buildQueryString(getCurrentFilters());
        const response = await fetch(`/api/summary/${query}`);
        const data = await response.json();

        const totalEl = document.getElementById("total-events");
        const validatedEl = document.getElementById("validated-events");
        const historicalEl = document.getElementById("historical-events");
        const impactEl = document.getElementById("high-impact-events");

        const industryEl = document.getElementById("top-industry");
        const attackEl = document.getElementById("top-attack-type");
        const regionEl = document.getElementById("top-region");
        const verificationEl = document.getElementById("top-verification-level");

        if (totalEl) totalEl.textContent = data.total_events ?? "--";
        if (validatedEl) {
            validatedEl.textContent =
                data.validated_events !== undefined ? data.validated_events : "--";
        }
        if (historicalEl) {
            historicalEl.textContent =
                data.historical_events !== undefined ? data.historical_events : "--";
        }
        if (impactEl) {
            impactEl.textContent =
                data.high_impact_events !== undefined ? data.high_impact_events : "--";
        }

        if (industryEl) industryEl.textContent = data.top_industry ?? "—";
        if (attackEl) attackEl.textContent = data.top_attack_type ?? "—";
        if (regionEl) regionEl.textContent = data.top_region ?? "—";
        if (verificationEl) {
            verificationEl.textContent = formatLabel(data.top_verification_level);
        }
    } catch (err) {
        console.error("Failed to load summary:", err);
    }
}

async function loadEvents() {
    try {
        const query = buildEventsQuery(getCurrentFilters(), currentPage);

        const response = await fetch(`/api/events/${query}`);
        const events = await response.json();

        lastLoadedEventCount = events.length;

        const container = document.getElementById("event-feed");
        const countEl = document.getElementById("feed-count");

        container.innerHTML = "";

        if (countEl) {
            const start = lastLoadedEventCount ? ((currentPage - 1) * EVENTS_PAGE_SIZE) + 1 : 0;
            const end = ((currentPage - 1) * EVENTS_PAGE_SIZE) + lastLoadedEventCount;
            countEl.textContent = lastLoadedEventCount ? `Showing ${start}–${end}` : "No results";
        }

        if (!events.length) {
            if (currentPage > 1) {
                currentPage -= 1;
                await loadEvents();
                return;
            }

            container.innerHTML = "<p class='placeholder-list'>No events found.</p>";
            updatePaginationControls();
            return;
        }

        events.forEach(event => {
            const el = document.createElement("article");
            el.className = "event-card";

            const timelineLabel =
                event.record_origin === "historical_dataset"
                    ? `Occurred ${event.event_occurred_at
                          ? new Date(event.event_occurred_at).toLocaleDateString()
                          : "Unknown"}`
                    : `Last seen ${event.last_seen_at
                          ? new Date(event.last_seen_at).toLocaleDateString()
                          : "Unknown"}`;

            const detailLine = `Status: ${formatLabel(event.event_status)} • Verification: ${formatLabel(event.verification_level)} • Origin: ${formatLabel(event.record_origin)}`;
            
            el.innerHTML = `
                <h3>${event.canonical_title || "Untitled Event"}</h3>

                <p class="event-summary">
                    ${event.summary_short || "No summary available."}
                </p>

                <div class="event-meta">
                    <span class="meta-pill">${event.victim_display_label || event.victim_org_name || "Unknown organization"}</span>
                    <span class="meta-pill">${event.country || event.region || "Unknown geography"}</span>
                    <span class="meta-pill">${event.attack_type || "Unknown attack type"}</span>
                </div>

                <div class="event-detail-line">${detailLine}</div>
                <div class="event-timeline">${timelineLabel}</div>
            `;

            container.appendChild(el);
        });

        updatePaginationControls();
    } catch (err) {
        console.error("Failed to load events:", err);
    }
}

function updatePaginationControls() {
    const prevButton = document.getElementById("pagination-prev");
    const nextButton = document.getElementById("pagination-next");
    const statusEl = document.getElementById("pagination-status");

    if (prevButton) {
        prevButton.disabled = currentPage <= 1;
    }

    if (nextButton) {
        nextButton.disabled = lastLoadedEventCount < EVENTS_PAGE_SIZE;
    }

    if (statusEl) {
        statusEl.textContent = `Page ${currentPage}`;
    }
}

let map;
let choroplethLayer;

function normalizeCountryName(value) {
    if (!value) {
        return "";
    }

    const normalized = value.toString().trim().toLowerCase();

    const aliases = {
        "united states of america": "united states",
        "usa": "united states",
        "us": "united states",
        "u.s.": "united states",
        "u.s.a.": "united states",
        "uk": "united kingdom",
        "russian federation": "russia",
        "korea, republic of": "south korea",
        "republic of korea": "south korea",
        "korea south": "south korea",
        "viet nam": "vietnam",
        "czechia": "czech republic",
    };

    return aliases[normalized] || normalized;
}

function getCountryEventCounts(points) {
    const counts = new Map();

    points.forEach(point => {
        const key = normalizeCountryName(point.country);
        if (!key) {
            return;
        }

        counts.set(key, (counts.get(key) || 0) + 1);
    });

    return counts;
}

function getCountryFillColor(count) {
    if (count >= 10) return "#1e3a8a";
    if (count >= 5) return "#1d4ed8";
    if (count >= 3) return "#2563eb";
    if (count >= 1) return "#60a5fa";
    return "#f1f5f9";
}

function getFeatureCountryName(feature) {
    return (
        feature?.properties?.name ||
        feature?.properties?.NAME ||
        feature?.properties?.admin ||
        feature?.properties?.ADMIN ||
        ""
    );
}

async function loadMapPoints() {
    try {
        const query = buildQueryString(getCurrentFilters());
        const [pointsResponse, worldGeoJson] = await Promise.all([
            fetch(`/api/summary/map${query}`),
            loadWorldGeoJson(),
        ]);

        const points = await pointsResponse.json();
        const countryCounts = getCountryEventCounts(points);

        if (!map) {
            map = L.map("map", {
                zoomControl: true,
                scrollWheelZoom: true,
            }).setView([20, 0], 2);

            L.tileLayer("https://{s}.basemaps.cartocdn.com/light_nolabels/{z}/{x}/{y}{r}.png", {
                attribution: "&copy; OpenStreetMap contributors &copy; CARTO",
                subdomains: "abcd",
                maxZoom: 19,
            }).addTo(map);
        }

        if (choroplethLayer) {
            map.removeLayer(choroplethLayer);
        }

        choroplethLayer = L.geoJSON(worldGeoJson, {
            style: feature => {
                const countryName = normalizeCountryName(getFeatureCountryName(feature));
                const count = countryCounts.get(countryName) || 0;

                return {
                    fillColor: getCountryFillColor(count),
                    weight: 1,
                    opacity: 1,
                    color: "#e2e8f0",
                    fillOpacity: count > 0 ? 0.85 : 0.15,
                };
            },
            onEachFeature: (feature, layer) => {
                const rawCountryName = getFeatureCountryName(feature);
                const countryName = normalizeCountryName(rawCountryName);
                const count = countryCounts.get(countryName) || 0;

                layer.bindPopup(`
                    <strong>${rawCountryName || "Unknown country"}</strong><br>
                    ${count} event${count === 1 ? "" : "s"}
                `);

                layer.on("mouseover", () => {
                    layer.setStyle({
                        weight: 2,
                        color: "#94a3b8",
                    });
                });

                layer.on("mouseout", () => {
                    choroplethLayer.resetStyle(layer);
                });
            },
        }).addTo(map);

        if (!points.length) {
            map.setView([20, 0], 2);
            return;
        }

        const mappedLatLngs = points
            .filter(point => point.lat != null && point.lng != null)
            .map(point => [Number(point.lat), Number(point.lng)])
            .filter(([lat, lng]) => !Number.isNaN(lat) && !Number.isNaN(lng));

        if (mappedLatLngs.length === 1) {
            map.setView(mappedLatLngs[0], 4);
        } else if (mappedLatLngs.length > 1) {
            map.fitBounds(mappedLatLngs, { padding: [30, 30] });

            if (map.getZoom() > 5) {
                map.setZoom(5);
            }
        } else {
            map.setView([20, 0], 2);
        }
    } catch (err) {
        console.error("Failed to load map:", err);
    }
}

function setLoading(isLoading) {
    const sections = [
        document.getElementById("event-feed"),
        document.getElementById("map"),
    ];

    sections.forEach(section => {
        if (!section) {
            return;
        }

        if (isLoading) {
            section.classList.add("loading");
        } else {
            section.classList.remove("loading");
        }
    });
}

async function refreshDashboard() {
    await loadFilters();
    await loadSummary();
    await loadMapPoints();
    await loadEvents();
}

async function handleFilterChange() {
    setLoading(true);

    try {
        currentPage = 1;
        const current = getCurrentFilters();
        saveFilters(current);
        await refreshDashboard();
    } finally {
        setLoading(false);
    }
}

function enableDatePickerOpenOnClick(inputId) {
    const input = document.getElementById(inputId);

    if (!input) {
        return;
    }

    input.addEventListener("click", () => {
        if (typeof input.showPicker === "function") {
            input.showPicker();
        }
    });

    input.addEventListener("focus", () => {
        if (typeof input.showPicker === "function") {
            input.showPicker();
        }
    });
}

async function resetFilters() {
    setLoading(true);

    try {
        currentPage = 1;
        const defaults = getDefaultFilters();
        saveFilters(defaults);
        applyFiltersToControls(defaults);
        await refreshDashboard();
    } finally {
        setLoading(false);
    }
}

enableDatePickerOpenOnClick("filter-start-date");
enableDatePickerOpenOnClick("filter-end-date");

[
    "filter-industry",
    "filter-region",
    "filter-country",
    "filter-attack-type",
    "filter-start-date",
    "filter-end-date",
].forEach(id => {
    const el = document.getElementById(id);
    if (el) {
        el.addEventListener("change", handleFilterChange);
    }
});

const resetFiltersButton = document.getElementById("reset-filters");
if (resetFiltersButton) {
    resetFiltersButton.addEventListener("click", resetFilters);
}

const paginationPrevButton = document.getElementById("pagination-prev");
if (paginationPrevButton) {
    paginationPrevButton.addEventListener("click", async () => {
        if (currentPage <= 1) {
            return;
        }

        setLoading(true);
        try {
            currentPage -= 1;
            await refreshDashboard();
        } finally {
            setLoading(false);
        }
    });
}

const paginationNextButton = document.getElementById("pagination-next");
if (paginationNextButton) {
    paginationNextButton.addEventListener("click", async () => {
        if (lastLoadedEventCount < EVENTS_PAGE_SIZE) {
            return;
        }

        setLoading(true);
        try {
            currentPage += 1;
            await refreshDashboard();
        } finally {
            setLoading(false);
        }
    });
}

setLoading(true);

refreshDashboard()
    .finally(() => {
        setLoading(false);
    });