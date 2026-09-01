/**
 * AI Tactical Command And Deployment Simulator — Digital Twin Renderer
 *
 * Phase 2: Digital Twin
 * Renders an interactive SVG topology of the simulated national
 * infrastructure, with clickable sectors and assets plus a detail panel.
 *
 * Phase 20C: Hierarchical tier layout with exterior labels, zoom/pan,
 * and clearly readable sector/asset names at 14–16 px.
 */

(function () {
    "use strict";

    // ------------------------------------------------------------------
    // Colour / status mapping
    // ------------------------------------------------------------------

    var STATUS_COLORS = {
        healthy:      { fill: "#22c55e", stroke: "#16a34a", glow: "rgba(34,197,94,0.35)" },
        warning:      { fill: "#f59e0b", stroke: "#d97706", glow: "rgba(245,158,11,0.35)" },
        compromised:  { fill: "#ef4444", stroke: "#dc2626", glow: "rgba(239,68,68,0.40)" },
        isolated:     { fill: "#64748b", stroke: "#475569", glow: "rgba(100,116,139,0.25)" },
        under_attack: { fill: "#f43f5e", stroke: "#e11d48", glow: "rgba(244,63,94,0.50)" }
    };

    var CRITICALITY_COLORS = {
        critical: "#ef4444",
        high:     "#f59e0b",
        medium:   "#38bdf8",
        low:      "#64748b"
    };

    // ------------------------------------------------------------------
    // Layout constants
    // ------------------------------------------------------------------

    // Hierarchical tier layout within a 1600 x 1120 coordinate space.
    //
    // Tier 0 (y=140):  military                      — top source
    // Tier 1 (y=340):  government, telecom            — primary peers
    // Tier 2 (y=540):  energy, banking, healthcare    — critical infra
    // Tier 3 (y=740):  education, commercial          — downstream
    //
    // Assets sit in a sub-row 190 px below their parent sector (y + 190).

    var TIER_Y = [140, 340, 540, 740];

    var SECTOR_POS = {
        military:   { x:  800, y: TIER_Y[0] },

        government: { x:  420, y: TIER_Y[1] },
        telecom:    { x: 1180, y: TIER_Y[1] },

        energy:     { x:  260, y: TIER_Y[2] },
        banking:    { x:  730, y: TIER_Y[2] },
        healthcare: { x: 1200, y: TIER_Y[2] },

        education:  { x:  420, y: TIER_Y[3] },
        commercial: { x: 1000, y: TIER_Y[3] }
    };

    var SVG_W         = 1600;
    var SVG_H         = 1120;
    var SECTOR_RADIUS = 52;      // circle radius for sector nodes
    var ASSET_RADIUS  = 18;      // circle radius for asset nodes
    var ASSET_ORBIT_Y = 200;     // vertical distance from sector centre to asset row
    var ASSET_ORBIT_X = 100;     // horizontal spread: asset i offset = (i - (n-1)/2) * ASSET_ORBIT_X
    var SVG_NS        = "http://www.w3.org/2000/svg";

    // ------------------------------------------------------------------
    // Data
    // ------------------------------------------------------------------

    var twinData       = null;
    var selectedSector = null;
    var selectedAsset  = null;

    // ------------------------------------------------------------------
    // SVG helper utilities
    // ------------------------------------------------------------------

    function svgEl(tag, attrs) {
        var el = document.createElementNS(SVG_NS, tag);
        if (attrs) {
            Object.keys(attrs).forEach(function (k) {
                el.setAttribute(k, attrs[k]);
            });
        }
        return el;
    }

    function svgText(x, y, text, attrs) {
        var defaults = {
            x: x, y: y,
            "text-anchor": "middle",
            "dominant-baseline": "central",
            fill: "#e2e8f0",
            "font-size": "14",
            "font-family": "Segoe UI, Arial, sans-serif",
            "pointer-events": "none"
        };
        if (attrs) Object.keys(attrs).forEach(function (k) { defaults[k] = attrs[k]; });
        var t = svgEl("text", defaults);
        t.textContent = text;
        return t;
    }

    // Split a name into at most 2 display lines.
    // Splits on " / " first, then on " & ", then at the space nearest the midpoint.
    function splitLabel(name) {
        if (name.indexOf(" / ") !== -1) return name.split(" / ").slice(0, 2);
        if (name.length <= 11) return [name];
        var ampIdx = name.indexOf(" & ");
        if (ampIdx !== -1) {
            return [name.slice(0, ampIdx), name.slice(ampIdx + 1)];
        }
        var mid = Math.floor(name.length / 2);
        var best = -1, bestDist = Infinity;
        for (var i = 0; i < name.length; i++) {
            if (name[i] === " ") {
                var d = Math.abs(i - mid);
                if (d < bestDist) { bestDist = d; best = i; }
            }
        }
        if (best === -1) return [name];
        return [name.slice(0, best), name.slice(best + 1)];
    }

    // ------------------------------------------------------------------
    // Compute asset screen positions
    // ------------------------------------------------------------------

    // Assets are arranged in a horizontal row below their parent sector.
    // Returns {ax, ay} for asset index i of count n under sector at (sx, sy).
    function assetPos(sx, sy, i, n) {
        var ax = sx + (i - (n - 1) / 2) * ASSET_ORBIT_X;
        var ay = sy + ASSET_ORBIT_Y;
        return { x: ax, y: ay };
    }

    // ------------------------------------------------------------------
    // Render dependency edges (sector → sector)
    // ------------------------------------------------------------------

    function renderEdges(g, data) {
        data.dependencies.forEach(function (dep) {
            var src = SECTOR_POS[dep.source];
            var tgt = SECTOR_POS[dep.target];
            if (!src || !tgt) return;

            // Quadratic bezier with a gentle lateral bow
            var mx = (src.x + tgt.x) / 2;
            var my = (src.y + tgt.y) / 2;
            var dx = tgt.x - src.x;
            var dy = tgt.y - src.y;
            var cx = mx - dy * 0.12;
            var cy = my + dx * 0.12;

            var path = svgEl("path", {
                d: "M" + src.x + "," + src.y + " Q" + cx + "," + cy + " " + tgt.x + "," + tgt.y,
                fill: "none",
                stroke: dep.active ? "#334155" : "#1e293b",
                "stroke-width": dep.active ? "2" : "1.5",
                "stroke-dasharray": dep.active ? "none" : "6,4",
                "class": "edge-path",
                "data-source": dep.source,
                "data-target": dep.target
            });
            g.appendChild(path);

            // Arrowhead at target node edge
            var angle = Math.atan2(tgt.y - cy, tgt.x - cx);
            var arrowX = tgt.x - Math.cos(angle) * (SECTOR_RADIUS + 10);
            var arrowY = tgt.y - Math.sin(angle) * (SECTOR_RADIUS + 10);
            g.appendChild(svgEl("polygon", {
                points: arrowPoints(arrowX, arrowY, angle, 8),
                fill: dep.active ? "#475569" : "#1e293b",
                "class": "edge-arrow"
            }));
        });
    }

    function arrowPoints(x, y, angle, size) {
        var a1 = angle + Math.PI * 0.8;
        var a2 = angle - Math.PI * 0.8;
        return (x + Math.cos(angle) * size)       + "," + (y + Math.sin(angle) * size)       + " " +
               (x + Math.cos(a1)    * size * 0.6) + "," + (y + Math.sin(a1)    * size * 0.6) + " " +
               (x + Math.cos(a2)    * size * 0.6) + "," + (y + Math.sin(a2)    * size * 0.6);
    }

    // ------------------------------------------------------------------
    // Render asset connector lines (sector → asset)
    // ------------------------------------------------------------------

    function renderAssetConnectors(g, data) {
        Object.keys(data.sectors).forEach(function (sid) {
            var pos   = SECTOR_POS[sid];
            if (!pos) return;
            var n     = data.sectors[sid].assets.length;
            data.sectors[sid].assets.forEach(function (asset, i) {
                var ap = assetPos(pos.x, pos.y, i, n);
                g.appendChild(svgEl("line", {
                    x1: pos.x, y1: pos.y + SECTOR_RADIUS,
                    x2: ap.x,  y2: ap.y  - ASSET_RADIUS,
                    stroke: "#1e293b", "stroke-width": "1.2",
                    "class": "asset-connector"
                }));
            });
        });
    }

    // ------------------------------------------------------------------
    // Render attack-path overlay
    // ------------------------------------------------------------------

    function renderAttackPaths(g, data) {
        if (!data.attack_paths || data.attack_paths.length === 0) return;
        data.attack_paths.forEach(function (path) {
            for (var i = 0; i < path.length - 1; i++) {
                var src = SECTOR_POS[path[i]];
                var tgt = SECTOR_POS[path[i + 1]];
                if (!src || !tgt) continue;
                g.appendChild(svgEl("line", {
                    x1: src.x, y1: src.y, x2: tgt.x, y2: tgt.y,
                    stroke: "#ef4444", "stroke-width": "4",
                    "stroke-dasharray": "10,5", opacity: "0.75",
                    "class": "attack-path-line"
                }));
            }
        });
    }

    // ------------------------------------------------------------------
    // Render sector nodes
    // ------------------------------------------------------------------

    function renderSectors(g, data) {
        Object.keys(data.sectors).forEach(function (sid) {
            var sector = data.sectors[sid];
            var pos    = SECTOR_POS[sid];
            if (!pos) return;
            var colors = STATUS_COLORS[sector.status] || STATUS_COLORS.healthy;

            var group = svgEl("g", {
                "class": "sector-node",
                "data-sector": sid,
                transform: "translate(" + pos.x + "," + pos.y + ")",
                style: "cursor:pointer;"
            });

            // Glow halo
            group.appendChild(svgEl("circle", {
                r: SECTOR_RADIUS + 10, fill: colors.glow, "class": "sector-glow"
            }));

            // Main circle
            group.appendChild(svgEl("circle", {
                r: SECTOR_RADIUS,
                fill: "#111827",
                stroke: colors.fill,
                "stroke-width": "3",
                "class": "sector-circle"
            }));

            // Icon — centred inside circle
            group.appendChild(svgText(0, -8, sector.icon, {
                "font-size": "28",
                fill: "#f1f5f9"
            }));

            // Sector name — rendered BELOW the circle as exterior label.
            // font-size is in SVG user units; with a 1600-wide viewBox displayed
            // at ~900 px the scale is ~0.56, so 30 SVG units ≈ 17 CSS px on screen.
            var nameLines  = splitLabel(sector.name);
            var nameStartY = SECTOR_RADIUS + 28;   // gap below circle edge
            var lineH      = 30;                   // px between wrapped lines
            nameLines.forEach(function (line, li) {
                group.appendChild(svgText(0, nameStartY + li * lineH, line, {
                    "font-size": "30",
                    "font-weight": "700",
                    "letter-spacing": "0.5",
                    fill: colors.fill
                }));
            });

            group.addEventListener("click", function (e) {
                e.stopPropagation();
                showSectorDetail(sid);
            });

            g.appendChild(group);
        });
    }

    // ------------------------------------------------------------------
    // Render asset nodes
    // ------------------------------------------------------------------

    function renderAssets(g, data) {
        Object.keys(data.sectors).forEach(function (sid) {
            var sector = data.sectors[sid];
            var pos    = SECTOR_POS[sid];
            if (!pos) return;
            var n = sector.assets.length;

            sector.assets.forEach(function (asset, i) {
                var ap     = assetPos(pos.x, pos.y, i, n);
                var colors = STATUS_COLORS[asset.status] || STATUS_COLORS.healthy;
                var crit   = CRITICALITY_COLORS[asset.criticality] || CRITICALITY_COLORS.medium;

                var ag = svgEl("g", {
                    "class": "asset-node",
                    "data-asset": asset.asset_id,
                    "data-sector": sid,
                    transform: "translate(" + ap.x + "," + ap.y + ")",
                    style: "cursor:pointer;"
                });

                // Subtle glow for critical assets
                if (asset.criticality === "critical" || asset.criticality === "high") {
                    ag.appendChild(svgEl("circle", {
                        r: ASSET_RADIUS + 5,
                        fill: colors.glow,
                        "class": "asset-glow"
                    }));
                }

                // Circle
                ag.appendChild(svgEl("circle", {
                    r: ASSET_RADIUS,
                    fill: "#0d1117",
                    stroke: colors.fill,
                    "stroke-width": "2.5"
                }));

                // Criticality ring (inner)
                ag.appendChild(svgEl("circle", {
                    r: 5, fill: crit, cy: 0
                }));

                // Asset name — exterior label below the asset circle.
                // 22 SVG units ≈ 12 CSS px at the 1600-viewBox scale.
                var labelLines  = splitLabel(asset.name);
                var labelStartY = ASSET_RADIUS + 22;
                var labelLineH  = 22;
                labelLines.forEach(function (line, li) {
                    // paint-order stroke creates a dark halo so text is legible over edges
                    ag.appendChild(svgText(0, labelStartY + li * labelLineH, line, {
                        "font-size": "22",
                        fill: "#cbd5e1",
                        "font-weight": "600",
                        "paint-order": "stroke",
                        stroke: "#0d1117",
                        "stroke-width": "5",
                        "stroke-linejoin": "round"
                    }));
                });

                ag.addEventListener("click", function (e) {
                    e.stopPropagation();
                    showAssetDetail(asset.asset_id);
                });

                g.appendChild(ag);
            });
        });
    }

    // ------------------------------------------------------------------
    // Main render entry — builds scene graph inside a pannable group
    // ------------------------------------------------------------------

    var _panG    = null;  // the <g> we pan/zoom
    var _scale   = 1;
    var _tx      = 0;
    var _ty      = 0;

    function applyTransform() {
        if (_panG) {
            _panG.setAttribute("transform",
                "translate(" + _tx + "," + _ty + ") scale(" + _scale + ")");
        }
    }

    function renderTopology() {
        var svg = document.getElementById("topologySvg");
        if (!svg) return;
        svg.innerHTML = "";

        // Defs — glow filter
        var defs   = svgEl("defs");
        var filter = svgEl("filter", { id: "glow", x: "-30%", y: "-30%", width: "160%", height: "160%" });
        filter.appendChild(svgEl("feGaussianBlur", { stdDeviation: "4", result: "blur" }));
        var merge = svgEl("feMerge");
        merge.appendChild(svgEl("feMergeNode", { "in": "blur" }));
        merge.appendChild(svgEl("feMergeNode", { "in": "SourceGraphic" }));
        filter.appendChild(merge);
        defs.appendChild(filter);
        svg.appendChild(defs);

        // Background
        svg.appendChild(svgEl("rect", {
            x: 0, y: 0, width: SVG_W, height: SVG_H,
            fill: "#07090f",
            "class": "topo-bg"
        }));

        // Tier label banners (subtle horizontal guide lines)
        var tierLabels = [
            { y: TIER_Y[0], text: "SOURCE / COMMAND" },
            { y: TIER_Y[1], text: "CORE INFRASTRUCTURE" },
            { y: TIER_Y[2], text: "CRITICAL SERVICES" },
            { y: TIER_Y[3], text: "SUPPORTING SECTORS" }
        ];
        var bannerG = svgEl("g", { "class": "tier-banners" });
        tierLabels.forEach(function (tier) {
            bannerG.appendChild(svgEl("line", {
                x1: 40, y1: tier.y - SECTOR_RADIUS - 30,
                x2: SVG_W - 40, y2: tier.y - SECTOR_RADIUS - 30,
                stroke: "#1e293b", "stroke-width": "1", "stroke-dasharray": "4,6"
            }));
            bannerG.appendChild(svgText(56, tier.y - SECTOR_RADIUS - 16, tier.text, {
                "font-size": "10",
                fill: "#334155",
                "text-anchor": "start",
                "font-weight": "600",
                "letter-spacing": "1.5",
                "text-transform": "uppercase"
            }));
        });

        // All scene elements go into a single pannable/scalable group
        var panG = svgEl("g", { "class": "pan-group" });
        _panG = panG;
        applyTransform();

        panG.appendChild(bannerG);

        var edgeG = svgEl("g", { "class": "edges" });
        renderEdges(edgeG, twinData);
        panG.appendChild(edgeG);

        var atkG = svgEl("g", { "class": "attack-paths" });
        renderAttackPaths(atkG, twinData);
        panG.appendChild(atkG);

        var connG = svgEl("g", { "class": "asset-connectors" });
        renderAssetConnectors(connG, twinData);
        panG.appendChild(connG);

        var sectorG = svgEl("g", { "class": "sectors" });
        renderSectors(sectorG, twinData);
        panG.appendChild(sectorG);

        var assetG = svgEl("g", { "class": "assets" });
        renderAssets(assetG, twinData);
        panG.appendChild(assetG);

        svg.appendChild(panG);

        // Zoom hint
        var hint = svgEl("text", {
            x: SVG_W - 16, y: SVG_H - 10,
            "text-anchor": "end",
            fill: "#334155",
            "font-size": "11",
            "font-family": "Segoe UI, Arial, sans-serif",
            "pointer-events": "none"
        });
        hint.textContent = "Scroll to zoom  ·  Drag to pan";
        svg.appendChild(hint);

        setupZoomPan(svg);
    }

    // ------------------------------------------------------------------
    // Zoom / pan interaction
    // ------------------------------------------------------------------

    function setupZoomPan(svg) {
        _scale = 1; _tx = 0; _ty = 0;
        applyTransform();

        var isDragging = false;
        var dragStartX = 0, dragStartY = 0;
        var dragTx = 0, dragTy = 0;

        svg.addEventListener("mousedown", function (e) {
            // Ignore clicks on nodes (they stopPropagation)
            isDragging = true;
            dragStartX = e.clientX;
            dragStartY = e.clientY;
            dragTx     = _tx;
            dragTy     = _ty;
            svg.style.cursor = "grabbing";
            e.preventDefault();
        });

        window.addEventListener("mousemove", function (e) {
            if (!isDragging) return;
            _tx = dragTx + (e.clientX - dragStartX);
            _ty = dragTy + (e.clientY - dragStartY);
            applyTransform();
        });

        window.addEventListener("mouseup", function () {
            isDragging = false;
            svg.style.cursor = "default";
        });

        svg.addEventListener("wheel", function (e) {
            e.preventDefault();
            var rect   = svg.getBoundingClientRect();
            var mouseX = (e.clientX - rect.left) / (rect.width  / SVG_W);
            var mouseY = (e.clientY - rect.top)  / (rect.height / SVG_H);

            var delta  = e.deltaY < 0 ? 1.12 : 0.89;
            var newScale = Math.max(0.35, Math.min(3.0, _scale * delta));
            var ratio    = newScale / _scale;

            // Zoom towards the mouse cursor position
            _tx    = mouseX - ratio * (mouseX - _tx);
            _ty    = mouseY - ratio * (mouseY - _ty);
            _scale = newScale;
            applyTransform();
        }, { passive: false });

        // Double-click resets view
        svg.addEventListener("dblclick", function (e) {
            // Only reset if click was on background (not a node)
            if (e.target.classList.contains("topo-bg") ||
                e.target.tagName === "svg") {
                _scale = 1; _tx = 0; _ty = 0;
                applyTransform();
            }
        });
    }

    // ------------------------------------------------------------------
    // Summary bar
    // ------------------------------------------------------------------

    function updateSummaryBar() {
        var s = twinData.summary;
        setText("sumSectors",     "Sectors: " + s.total_sectors);
        setText("sumAssets",      "Assets: " + s.total_assets);
        setText("sumHealthy",     "Healthy: " + s.healthy);
        setText("sumWarning",     "Warning: " + s.warning);
        setText("sumCompromised", "Compromised: " + s.compromised);
        setText("sumAttack",      "Attack Paths: " + s.attack_paths);
    }

    function setText(id, val) {
        var el = document.getElementById(id);
        if (el) el.textContent = val;
    }

    // ------------------------------------------------------------------
    // Detail panel — Sector
    // ------------------------------------------------------------------

    function showSectorDetail(sectorId) {
        selectedSector = sectorId;
        selectedAsset  = null;

        var sector = twinData.sectors[sectorId];
        if (!sector) return;

        hide("detailPlaceholder");
        hide("assetDetail");
        show("sectorDetail");

        setText("sectorName", sector.icon + "  " + sector.name);

        var badge = document.getElementById("sectorBadge");
        badge.textContent = sector.status.toUpperCase();
        badge.className   = "badge badge--" + sector.status;

        setText("sectorThreat",      sector.threat_level.toUpperCase());
        setText("sectorAssets",      sector.asset_count);
        setText("sectorHealthy",     sector.healthy);
        setText("sectorWarning",     sector.warning);
        setText("sectorCompromised", sector.compromised);
        setText("sectorDescription", sector.description);

        var depsEl = document.getElementById("sectorDeps");
        var inEl   = document.getElementById("sectorIncoming");
        var outEl  = document.getElementById("sectorOutgoing");
        depsEl.innerHTML = "";
        inEl.innerHTML   = "";
        outEl.innerHTML  = "";

        twinData.dependencies.forEach(function (dep) {
            var srcName = twinData.sectors[dep.source] ? twinData.sectors[dep.source].name : dep.source;
            var tgtName = twinData.sectors[dep.target] ? twinData.sectors[dep.target].name : dep.target;
            if (dep.source === sectorId) {
                outEl.appendChild(li(srcName + " \u2192 " + tgtName + (dep.label ? " (" + dep.label + ")" : "")));
                depsEl.appendChild(li("\u2192 " + tgtName));
            }
            if (dep.target === sectorId) {
                inEl.appendChild(li(srcName + " \u2192 " + tgtName + (dep.label ? " (" + dep.label + ")" : "")));
                depsEl.appendChild(li(srcName + " \u2192"));
            }
        });

        if (depsEl.children.length === 0) depsEl.appendChild(li("None"));
        if (inEl.children.length   === 0) inEl.appendChild(li("None"));
        if (outEl.children.length  === 0) outEl.appendChild(li("None"));

        highlightSector(sectorId);
    }

    // ------------------------------------------------------------------
    // Detail panel — Asset
    // ------------------------------------------------------------------

    function showAssetDetail(assetId) {
        selectedAsset = assetId;

        var asset = null, parentSector = null;
        Object.keys(twinData.sectors).forEach(function (sid) {
            twinData.sectors[sid].assets.forEach(function (a) {
                if (a.asset_id === assetId) { asset = a; parentSector = sid; }
            });
        });
        if (!asset) return;

        var sector = twinData.sectors[parentSector];

        hide("detailPlaceholder");
        hide("sectorDetail");
        show("assetDetail");

        setText("assetName", asset.name);
        var badge = document.getElementById("assetBadge");
        badge.textContent = asset.status.toUpperCase();
        badge.className   = "badge badge--" + asset.status;

        setText("assetSector",      sector.name);
        setText("assetCriticality", asset.criticality.toUpperCase());
        setText("assetThreatState", asset.threat_state || "None");

        var actEl = document.getElementById("assetActivity");
        actEl.innerHTML = "";
        if (asset.activity.length === 0) {
            actEl.appendChild(li("No simulated activity yet"));
        } else {
            asset.activity.forEach(function (a) { actEl.appendChild(li(a)); });
        }

        var depsEl = document.getElementById("assetDeps");
        depsEl.innerHTML = "";
        twinData.dependencies.forEach(function (dep) {
            if (dep.source === parentSector || dep.target === parentSector) {
                var srcName = twinData.sectors[dep.source] ? twinData.sectors[dep.source].name : dep.source;
                var tgtName = twinData.sectors[dep.target] ? twinData.sectors[dep.target].name : dep.target;
                depsEl.appendChild(li(srcName + " \u2192 " + tgtName));
            }
        });
        if (depsEl.children.length === 0) depsEl.appendChild(li("None"));
    }

    // ------------------------------------------------------------------
    // Highlight
    // ------------------------------------------------------------------

    function highlightSector(sectorId) {
        document.querySelectorAll(".sector-node").forEach(function (n) {
            if (n.getAttribute("data-sector") === sectorId) {
                n.classList.add("sector-node--selected");
            } else {
                n.classList.remove("sector-node--selected");
            }
        });
        document.querySelectorAll(".edge-path").forEach(function (e) {
            if (e.getAttribute("data-source") === sectorId ||
                e.getAttribute("data-target") === sectorId) {
                e.classList.add("edge-path--highlighted");
            } else {
                e.classList.remove("edge-path--highlighted");
            }
        });
    }

    function clearSelection() {
        selectedSector = null;
        selectedAsset  = null;
        show("detailPlaceholder");
        hide("sectorDetail");
        hide("assetDetail");
        document.querySelectorAll(".sector-node--selected").forEach(function (n) {
            n.classList.remove("sector-node--selected");
        });
        document.querySelectorAll(".edge-path--highlighted").forEach(function (e) {
            e.classList.remove("edge-path--highlighted");
        });
    }

    // ------------------------------------------------------------------
    // Utility
    // ------------------------------------------------------------------

    function show(id) { var e = document.getElementById(id); if (e) e.style.display = ""; }
    function hide(id) { var e = document.getElementById(id); if (e) e.style.display = "none"; }
    function li(text) {
        var el = document.createElement("li");
        el.textContent = text;
        return el;
    }

    // ------------------------------------------------------------------
    // Initialization
    // ------------------------------------------------------------------

    function init() {
        twinData = window.CYBER_TWIN_DATA;
        if (!twinData) {
            console.warn("[CYBER TWIN] No data found.");
            return;
        }

        renderTopology();
        updateSummaryBar();

        var sectorClose = document.getElementById("sectorDetailClose");
        if (sectorClose) sectorClose.addEventListener("click", clearSelection);
        var assetClose = document.getElementById("assetDetailClose");
        if (assetClose) assetClose.addEventListener("click", clearSelection);

        // Background click clears selection (mousedown already used for drag;
        // only clear when it was a true click — delta < 4 px)
        var svg = document.getElementById("topologySvg");
        if (svg) {
            var _mdX = 0, _mdY = 0;
            svg.addEventListener("mousedown", function (e) {
                _mdX = e.clientX; _mdY = e.clientY;
            });
            svg.addEventListener("click", function (e) {
                var dx = Math.abs(e.clientX - _mdX);
                var dy = Math.abs(e.clientY - _mdY);
                if (dx < 4 && dy < 4) clearSelection();
            });
        }

        console.log("[CYBER TWIN] Topology rendered — " +
            twinData.summary.total_sectors + " sectors, " +
            twinData.summary.total_assets + " assets.");
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
