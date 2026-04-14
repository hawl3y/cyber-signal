const FILTER_STORAGE_KEY = "cyber_signal_filters";

function getDefaultFilters() {
    return {
        industry: "",
        region: "",
        country: "",
        attack_type: "",
        time_range: "",
    };
}

function getCurrentFilters() {
    return {
        industry: document.getElementById("filter-industry")?.value || "",
        region: document.getElementById("filter-region")?.value || "",
        country: document.getElementById("filter-country")?.value || "",
        attack_type: document.getElementById("filter-attack-type")?.value || "",
        time_range: document.getElementById("filter-time-range")?.value || "",
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
    const timeRangeEl = document.getElementById("filter-time-range");

    if (industryEl) industryEl.value = filters.industry || "";
    if (regionEl) regionEl.value = filters.region || "";
    if (countryEl) countryEl.value = filters.country || "";
    if (attackTypeEl) attackTypeEl.value = filters.attack_type || "";
    if (timeRangeEl) timeRangeEl.value = filters.time_range || "";
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
        const industryEl = document.getElementById("top-industry");
        const attackEl = document.getElementById("top-attack-type");
        const impactEl = document.getElementById("high-impact-events");

        totalEl.textContent = data.total_events ?? "--";
        industryEl.textContent = data.top_industry ?? "—";
        attackEl.textContent = data.top_attack_type ?? "—";
        impactEl.textContent =
            data.high_impact_events !== undefined ? data.high_impact_events : "—";
    } catch (err) {
        console.error("Failed to load summary:", err);
    }
}

async function loadEvents() {
    try {
        const query = buildQueryString({
            ...getCurrentFilters(),
            limit: 20,
        });

        const response = await fetch(`/api/events/${query}`);
        const events = await response.json();

        const container = document.getElementById("event-feed");
        container.innerHTML = "";

        if (!events.length) {
            container.innerHTML = "<p class='placeholder-list'>No events found.</p>";
            return;
        }

        events.forEach(event => {
            const el = document.createElement("article");
            el.className = "event-card";

            el.innerHTML = `
                <h3>${event.canonical_title || "Untitled Event"}</h3>

                <p class="event-summary">
                    ${event.summary_short || "No summary available."}
                </p>

                <div class="event-meta">
                    <span class="meta-pill">${event.industry || "Unknown industry"}</span>
                    <span class="meta-pill">${event.country || event.region || "Unknown geography"}</span>
                    <span class="meta-pill">${event.attack_type || "Unknown attack type"}</span>
                    <span class="meta-pill">${event.victim_org_name || "Unknown organization"}</span>
                </div>

                <div class="event-submeta">
                    <span class="meta-pill">Confidence: ${event.confidence_level || "unknown"}</span>
                    <span class="meta-pill">Sources: ${event.source_count ?? 0}</span>
                    <span class="meta-pill">Recency: ${event.recency_bucket || "unknown"}</span>
                </div>
            `;

            container.appendChild(el);
        });
    } catch (err) {
        console.error("Failed to load events:", err);
    }
}

let map;
let markersLayer;

function getConfidenceMarkerStyle(confidenceLevel) {
    const level = (confidenceLevel || "").toLowerCase();

    if (level === "high") {
        return {
            radius: 9,
            color: "#ffffff",
            weight: 2,
            fillColor: "#b91c1c",
            fillOpacity: 0.9,
        };
    }

    if (level === "medium") {
        return {
            radius: 8,
            color: "#ffffff",
            weight: 2,
            fillColor: "#f59e0b",
            fillOpacity: 0.9,
        };
    }

    return {
        radius: 7,
        color: "#ffffff",
        weight: 2,
        fillColor: "#2563eb",
        fillOpacity: 0.8,
    };
}

function getCoordinateKey(lat, lng) {
    return `${Number(lat).toFixed(4)},${Number(lng).toFixed(4)}`;
}

function getJitteredLatLng(lat, lng, occurrenceIndex) {
    if (!occurrenceIndex) {
        return [lat, lng];
    }

    const angle = occurrenceIndex * 0.9;
    const distance = 0.18 * Math.ceil(occurrenceIndex / 2);

    const latOffset = Math.sin(angle) * distance;
    const lngOffset = Math.cos(angle) * distance;

    return [lat + latOffset, lng + lngOffset];
}

async function loadMapPoints() {
    try {
        const query = buildQueryString(getCurrentFilters());
        const response = await fetch(`/api/summary/map${query}`);
        const points = await response.json();

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

            markersLayer = L.layerGroup().addTo(map);
        }

        markersLayer.clearLayers();

        if (!points.length) {
            map.setView([20, 0], 2);
            return;
        }

        const bounds = [];
        const coordinateCounts = {};

        points.forEach(point => {
            const key = getCoordinateKey(point.lat, point.lng);
            const occurrenceIndex = coordinateCounts[key] || 0;
            coordinateCounts[key] = occurrenceIndex + 1;

            const [displayLat, displayLng] = getJitteredLatLng(
                Number(point.lat),
                Number(point.lng),
                occurrenceIndex
            );

            const marker = L.circleMarker(
                [displayLat, displayLng],
                getConfidenceMarkerStyle(point.confidence_level)
            );

            const locationLabel =
                point.country ||
                point.region ||
                "Unknown location";

            marker.bindPopup(`
                <strong>${point.title || "Untitled"}</strong><br>
                ${point.attack_type || "Unknown"}<br>
                ${locationLabel}<br>
                ${point.confidence_level || "unknown"} | Sources: ${point.source_count ?? 0}
            `);

            markersLayer.addLayer(marker);
            bounds.push([displayLat, displayLng]);
        });

        if (bounds.length === 1) {
            map.setView(bounds[0], 4);
        } else {
            map.fitBounds(bounds, { padding: [30, 30] });

            if (map.getZoom() > 5) {
                map.setZoom(5);
            }
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
        const current = getCurrentFilters();
        saveFilters(current);
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
    "filter-industry",
    "filter-region",
    "filter-country",
    "filter-attack-type",
    "filter-time-range",
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

setLoading(true);

refreshDashboard()
    .finally(() => {
        setLoading(false);
    });