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

        if (data.high_impact_events !== undefined) {
            impactEl.textContent = data.high_impact_events;
        } else {
            impactEl.textContent = "—";
        }
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
                    <span class="meta-pill">Status: ${event.event_status || "unknown"}</span>
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

function populateSelect(selectId, values) {
    const select = document.getElementById(selectId);
    select.innerHTML = '<option value="">All</option>';

    values.forEach(value => {
        const option = document.createElement("option");
        option.value = value;
        option.textContent = value;
        select.appendChild(option);
    });
}

async function loadFilters() {
    try {
        const current = {
            ...getCurrentFilters(),
            ...getFiltersFromUrl(),
        };
        const query = buildQueryString(current);

        const response = await fetch(`/api/filters/${query}`);
        const data = await response.json();

        populateSelect("filter-industry", data.industries || []);
        populateSelect("filter-region", data.regions || []);
        populateSelect("filter-country", data.countries || []);
        populateSelect("filter-city", data.cities || []);
        populateSelect("filter-attack-type", data.attack_types || []);
        populateSelect("filter-event-status", data.event_statuses || []);

        document.getElementById("filter-industry").value = current.industry;
        document.getElementById("filter-region").value = current.region;
        document.getElementById("filter-country").value = current.country;
        document.getElementById("filter-city").value = current.city;
        document.getElementById("filter-attack-type").value = current.attack_type;
        document.getElementById("filter-event-status").value = current.event_status;
    } catch (err) {
        console.error("Failed to load filters:", err);
    }
}

function getFiltersFromUrl() {
    const params = new URLSearchParams(window.location.search);

    return {
        industry: params.get("industry") || "",
        region: params.get("region") || "",
        country: params.get("country") || "",
        city: params.get("city") || "",
        attack_type: params.get("attack_type") || "",
        event_status: params.get("event_status") || "",
    };
}

function getCurrentFilters() {
    return {
        industry: document.getElementById("filter-industry")?.value || "",
        region: document.getElementById("filter-region")?.value || "",
        country: document.getElementById("filter-country")?.value || "",
        city: document.getElementById("filter-city")?.value || "",
        attack_type: document.getElementById("filter-attack-type")?.value || "",
        event_status: document.getElementById("filter-event-status")?.value || "",
    };
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

function updateUrlFromFilters(filters) {
    const query = buildQueryString(filters);
    const newUrl = `${window.location.pathname}${query}`;
    window.history.replaceState({}, "", newUrl);
}

async function handleFilterChange() {
    setLoading(true);

    const current = getCurrentFilters();
    updateUrlFromFilters(current);

    await loadFilters();
    await loadSummary();
    await loadMapPoints();
    await loadEvents();

    setLoading(false);
}

[
    "filter-industry",
    "filter-region",
    "filter-country",
    "filter-city",
    "filter-attack-type",
    "filter-event-status",
].forEach(id => {
    const el = document.getElementById(id);
    if (el) {
        el.addEventListener("change", handleFilterChange);
    }
});

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
                point.city ||
                point.country ||
                point.region ||
                "Unknown location";

            marker.bindPopup(`
                <strong>${point.title || "Untitled"}</strong><br>
                ${point.attack_type || "Unknown"}<br>
                ${locationLabel}<br>
                ${point.event_status || "unknown"} | ${point.confidence_level || "unknown"} | Sources: ${point.source_count ?? 0}
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
        if (!section) return;
        if (isLoading) {
            section.classList.add("loading");
        } else {
            section.classList.remove("loading");
        }
    });
}

setLoading(true);

loadFilters().then(async () => {
    await loadSummary();
    await loadMapPoints();
    await loadEvents();
    setLoading(false);
});