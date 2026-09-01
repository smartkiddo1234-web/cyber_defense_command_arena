/**
 * dashboard-charts.js — Phase 22: Apache ECharts live command-center visualizations.
 *
 * Renders 5 ECharts visualizations + critical alert + overall status from /api/dashboard/v2:
 *   1. Threat Activity — horizontal bar chart (sector heatmap)
 *   2. Threat Distribution — donut/pie chart (sector statuses)
 *   3. Confidence Trend — smooth area line chart (evidence timeline)
 *   4. Attack / Dependency Flow — force-directed graph
 *   5. Sector Risk — ranked horizontal bar chart
 *
 * Plus:
 *   9. Critical Alert banner (DOM update)
 *   Overall status strip indicators (DOM update)
 *
 * Live AI Recommendation, Commander Controls, and Deception panels are
 * updated by dashboard.js polling /api/dashboard.
 *
 * All data is synthetic and local.
 */
(function () {
    'use strict';

    /* ────────────── constants ────────────── */

    var POLL_INTERVAL = 3000; // ms

    var STATUS_COLORS = {
        healthy:      '#22c55e',
        warning:      '#f59e0b',
        compromised:  '#ef4444',
        isolated:     '#64748b',
        under_attack: '#f43f5e'
    };

    var CHART_BG   = 'transparent';
    var TEXT_COLOR  = '#94a3b8';
    var DIM_TEXT    = '#556280';
    var BORDER_CLR  = '#1c2438';
    var ACCENT      = '#5b8def';
    var DANGER      = '#ef4444';
    var WARNING     = '#f59e0b';
    var SUCCESS     = '#22c55e';

    /* ────────────── chart instance cache ────────────── */

    var instances = {};

    function getChart(id) {
        if (instances[id]) return instances[id];
        var dom = document.getElementById(id);
        if (!dom) return null;
        var c = echarts.getInstanceByDom(dom);
        if (c) { instances[id] = c; return c; }
        c = echarts.init(dom, null, { renderer: 'canvas' });
        instances[id] = c;
        return c;
    }

    /* ────────────── helpers ────────────── */

    function escapeHtml(s) {
        if (!s) return '';
        return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;')
                        .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    function setText(id, val) {
        var e = document.getElementById(id);
        if (e) e.textContent = val;
    }

    function cap(s) {
        return s ? s.charAt(0).toUpperCase() + s.slice(1) : '';
    }

    /* ────────────── 1. THREAT ACTIVITY BAR CHART ────────────── */

    function renderThreatBar(heatmap) {
        var chart = getChart('chartThreatActivity');
        if (!chart) return;

        if (!heatmap || heatmap.length === 0) {
            chart.clear();
            chart.setOption({
                title: {
                    text: 'No threat activity detected yet.',
                    subtext: 'Run the simulation to generate data.',
                    left: 'center', top: '40%',
                    textStyle: { color: TEXT_COLOR, fontSize: 13, fontWeight: 400 },
                    subtextStyle: { color: DIM_TEXT, fontSize: 11 }
                }
            });
            return;
        }

        var sectors = heatmap.map(function (h) { return cap(h.sector); }).reverse();
        var values  = heatmap.map(function (h) { return Math.round((h.max_signal || 0) * 100); }).reverse();
        var colors  = heatmap.map(function (h) {
            return STATUS_COLORS[h.status] || (h.max_signal > 0.7 ? DANGER : h.max_signal > 0.4 ? WARNING : ACCENT);
        }).reverse();

        chart.setOption({
            backgroundColor: CHART_BG,
            grid: { left: 110, right: 55, top: 8, bottom: 8 },
            xAxis: {
                type: 'value', max: 100,
                axisLabel: { color: DIM_TEXT, fontSize: 10, formatter: '{value}%' },
                splitLine: { lineStyle: { color: BORDER_CLR, type: 'dashed' } },
                axisLine: { show: false }
            },
            yAxis: {
                type: 'category', data: sectors,
                axisLabel: { color: TEXT_COLOR, fontSize: 11, fontWeight: 600 },
                axisLine: { show: false }, axisTick: { show: false }
            },
            series: [{
                type: 'bar', data: values, barWidth: 18,
                itemStyle: {
                    color: function (p) { return colors[p.dataIndex] || ACCENT; },
                    borderRadius: [0, 3, 3, 0]
                },
                label: {
                    show: true, position: 'right', color: TEXT_COLOR,
                    fontSize: 11, fontWeight: 600,
                    fontFamily: 'Consolas, monospace',
                    formatter: '{c}%'
                }
            }],
            tooltip: {
                trigger: 'axis', axisPointer: { type: 'shadow' },
                backgroundColor: '#1a2138', borderColor: '#2a3550',
                textStyle: { color: '#dce3ef', fontSize: 12 }
            },
            animationDuration: 400,
            animationEasing: 'cubicOut'
        });
    }

    /* ────────────── 2. THREAT DISTRIBUTION DONUT ────────────── */

    function renderDonut(dist) {
        var chart = getChart('chartThreatDistribution');
        if (!chart) return;

        if (!dist || Object.keys(dist).length === 0) {
            chart.clear();
            chart.setOption({
                title: {
                    text: 'No data', left: 'center', top: 'center',
                    textStyle: { color: TEXT_COLOR, fontSize: 13, fontWeight: 400 }
                }
            });
            return;
        }

        var total = 0;
        var data = [];
        Object.keys(dist).forEach(function (k) {
            total += dist[k];
            data.push({
                name: cap(k),
                value: dist[k],
                itemStyle: { color: STATUS_COLORS[k] || '#64748b' }
            });
        });

        chart.setOption({
            backgroundColor: CHART_BG,
            tooltip: {
                trigger: 'item',
                backgroundColor: '#1a2138', borderColor: '#2a3550',
                textStyle: { color: '#dce3ef', fontSize: 12 },
                formatter: '{b}: {c} ({d}%)'
            },
            legend: {
                bottom: 4, textStyle: { color: TEXT_COLOR, fontSize: 10 },
                itemWidth: 10, itemHeight: 10
            },
            series: [{
                type: 'pie',
                radius: ['42%', '70%'],
                center: ['50%', '45%'],
                avoidLabelOverlap: true,
                label: {
                    show: true, color: '#e2e8f0', fontSize: 12, fontWeight: 700,
                    formatter: '{c}'
                },
                labelLine: { show: false },
                emphasis: {
                    itemStyle: { shadowBlur: 10, shadowOffsetX: 0, shadowColor: 'rgba(0,0,0,0.3)' }
                },
                data: data,
                animationType: 'scale',
                animationEasing: 'elasticOut',
                animationDuration: 500
            }],
            graphic: [{
                type: 'text', left: 'center', top: '40%',
                style: {
                    text: String(total), fill: '#e2e8f0',
                    fontSize: 24, fontWeight: 700,
                    fontFamily: 'Segoe UI, sans-serif', textAlign: 'center'
                }
            }, {
                type: 'text', left: 'center', top: '52%',
                style: {
                    text: 'Sectors', fill: DIM_TEXT,
                    fontSize: 11, fontFamily: 'Segoe UI, sans-serif', textAlign: 'center'
                }
            }]
        });
    }

    /* ────────────── 3. CONFIDENCE TREND LINE CHART ────────────── */

    function renderConfidenceTrend(points) {
        var chart = getChart('chartConfidenceTrend');
        if (!chart) return;

        if (!points || points.length === 0) {
            chart.clear();
            chart.setOption({
                title: {
                    text: 'No confidence data yet.',
                    subtext: 'Run the simulation to generate evidence.',
                    left: 'center', top: '40%',
                    textStyle: { color: TEXT_COLOR, fontSize: 13, fontWeight: 400 },
                    subtextStyle: { color: DIM_TEXT, fontSize: 11 }
                }
            });
            return;
        }

        var labels  = [];
        var vals    = [];
        var n       = Math.min(points.length, 50);
        var pts     = points.slice(-n);

        pts.forEach(function (p, i) {
            labels.push(p.timestamp ? p.timestamp.slice(11, 19) : String(i + 1));
            vals.push(Math.round((p.confidence || 0) * 100));
        });

        chart.setOption({
            backgroundColor: CHART_BG,
            grid: { left: 44, right: 16, top: 20, bottom: 32 },
            xAxis: {
                type: 'category', data: labels,
                axisLabel: { color: DIM_TEXT, fontSize: 9, interval: Math.max(0, Math.floor(n / 6)) },
                axisLine: { lineStyle: { color: BORDER_CLR } }
            },
            yAxis: {
                type: 'value', min: 0, max: 100,
                axisLabel: { color: DIM_TEXT, fontSize: 10, formatter: '{value}%' },
                splitLine: { lineStyle: { color: BORDER_CLR, type: 'dashed' } },
                axisLine: { show: false }
            },
            series: [{
                type: 'line', data: vals, smooth: 0.3, symbol: 'circle', symbolSize: 5,
                lineStyle: { color: ACCENT, width: 2.5 },
                itemStyle: { color: ACCENT, borderWidth: 2, borderColor: '#0f1420' },
                areaStyle: {
                    color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                        { offset: 0, color: 'rgba(91,141,239,0.25)' },
                        { offset: 1, color: 'rgba(91,141,239,0.02)' }
                    ])
                },
                showSymbol: pts.length <= 20
            }],
            tooltip: {
                trigger: 'axis',
                backgroundColor: '#1a2138', borderColor: '#2a3550',
                textStyle: { color: '#dce3ef', fontSize: 12 },
                formatter: function (p) {
                    return p[0].axisValue + '<br/>Confidence: <b>' + p[0].value + '%</b>';
                }
            },
            animationDuration: 500
        });
    }

    /* ────────────── 4. ATTACK / DEPENDENCY FLOW GRAPH ────────────── */

    function renderAttackFlow(attackPaths, dependencies) {
        var chart = getChart('chartAttackFlow');
        if (!chart) return;

        var paths = (attackPaths && attackPaths.length > 0) ? attackPaths[0] : [];

        if (paths.length === 0 && (!dependencies || dependencies.length === 0)) {
            chart.clear();
            chart.setOption({
                title: {
                    text: 'No attack paths detected.',
                    subtext: 'Run the simulation to generate paths.',
                    left: 'center', top: '40%',
                    textStyle: { color: TEXT_COLOR, fontSize: 13, fontWeight: 400 },
                    subtextStyle: { color: DIM_TEXT, fontSize: 11 }
                }
            });
            return;
        }

        /* Build nodes from all sources */
        var nodeSet = {};
        var pathSet = {};

        paths.forEach(function (s) { nodeSet[s] = true; pathSet[s] = true; });

        (dependencies || []).forEach(function (d) {
            nodeSet[d.source] = true;
            nodeSet[d.target] = true;
        });

        var nodes = Object.keys(nodeSet).map(function (id) {
            var inPath = pathSet[id];
            return {
                name: cap(id),
                symbolSize: inPath ? 52 : 36,
                itemStyle: {
                    color: inPath ? '#7f1d1d' : '#151b2b',
                    borderColor: inPath ? DANGER : '#2a3550',
                    borderWidth: inPath ? 2.5 : 1.5
                },
                label: {
                    show: true, color: inPath ? '#fca5a5' : TEXT_COLOR,
                    fontSize: 11, fontWeight: inPath ? 700 : 500
                }
            };
        });

        var edges = [];

        /* Attack-path edges (red, solid) */
        for (var i = 0; i < paths.length - 1; i++) {
            edges.push({
                source: cap(paths[i]),
                target: cap(paths[i + 1]),
                lineStyle: { color: DANGER, width: 2.5, curveness: 0.1 }
            });
        }

        /* Dependency edges (dim, dashed) */
        (dependencies || []).forEach(function (d) {
            edges.push({
                source: cap(d.source),
                target: cap(d.target),
                lineStyle: { color: '#2a3550', width: 1, type: 'dashed', curveness: 0.15 }
            });
        });

        chart.setOption({
            backgroundColor: CHART_BG,
            tooltip: {
                backgroundColor: '#1a2138', borderColor: '#2a3550',
                textStyle: { color: '#dce3ef', fontSize: 12 }
            },
            legend: {
                data: ['Attack Path', 'Dependency'],
                bottom: 2, textStyle: { color: TEXT_COLOR, fontSize: 10 },
                itemWidth: 20, itemHeight: 3
            },
            series: [{
                type: 'graph',
                layout: 'force',
                roam: true,
                draggable: true,
                force: { repulsion: 350, gravity: 0.15, edgeLength: [80, 180] },
                categories: [
                    { name: 'Attack Path', itemStyle: { color: DANGER } },
                    { name: 'Dependency',  itemStyle: { color: '#2a3550' } }
                ],
                data: nodes,
                links: edges.map(function (e) {
                    e.category = e.lineStyle.color === DANGER ? 0 : 1;
                    return e;
                }),
                edgeSymbol: ['none', 'arrow'],
                edgeSymbolSize: [4, 10],
                emphasis: {
                    focus: 'adjacency',
                    lineStyle: { width: 3 }
                },
                label: { position: 'inside' }
            }],
            animationDuration: 800,
            animationEasing: 'cubicOut'
        });
    }

    /* ────────────── 5. SECTOR RISK RANKED BARS ────────────── */

    function renderSectorRisk(sectors) {
        var chart = getChart('chartSectorRisk');
        if (!chart) return;

        if (!sectors || sectors.length === 0) {
            chart.clear();
            chart.setOption({
                title: {
                    text: 'No sector data available.',
                    left: 'center', top: 'center',
                    textStyle: { color: TEXT_COLOR, fontSize: 13, fontWeight: 400 }
                }
            });
            return;
        }

        /* Already sorted descending by risk_score */
        var names  = sectors.map(function (s) { return s.name; }).reverse();
        var scores = sectors.map(function (s) { return Math.round(s.risk_score * 100); }).reverse();
        var colors = sectors.map(function (s) {
            return s.risk_score > 0.7 ? DANGER : s.risk_score > 0.4 ? WARNING : s.risk_score > 0 ? ACCENT : SUCCESS;
        }).reverse();

        chart.setOption({
            backgroundColor: CHART_BG,
            grid: { left: 130, right: 45, top: 4, bottom: 4 },
            xAxis: {
                type: 'value', max: 100,
                axisLabel: { show: false },
                splitLine: { lineStyle: { color: BORDER_CLR, type: 'dashed' } },
                axisLine: { show: false }
            },
            yAxis: {
                type: 'category', data: names,
                axisLabel: {
                    color: TEXT_COLOR, fontSize: 10, fontWeight: 600,
                    width: 120, overflow: 'truncate', ellipsis: '…'
                },
                axisLine: { show: false }, axisTick: { show: false }
            },
            series: [{
                type: 'bar', data: scores, barWidth: 14,
                itemStyle: {
                    color: function (p) { return colors[p.dataIndex] || SUCCESS; },
                    borderRadius: [0, 3, 3, 0]
                },
                label: {
                    show: true, position: 'right', color: TEXT_COLOR,
                    fontSize: 10, fontWeight: 600,
                    fontFamily: 'Consolas, monospace',
                    formatter: '{c}%'
                }
            }],
            tooltip: {
                trigger: 'axis', axisPointer: { type: 'shadow' },
                backgroundColor: '#1a2138', borderColor: '#2a3550',
                textStyle: { color: '#dce3ef', fontSize: 12 },
                formatter: function (p) {
                    var idx = sectors.length - 1 - p[0].dataIndex;
                    var s = sectors[idx];
                    var html = '<b>' + s.name + '</b><br/>';
                    html += 'Risk: ' + Math.round(s.risk_score * 100) + '%<br/>';
                    html += 'Status: ' + cap(s.status) + '<br/>';
                    if (s.latest_technique) html += 'Technique: ' + s.latest_technique;
                    return html;
                }
            },
            animationDuration: 400,
            animationEasing: 'cubicOut'
        });
    }

    /* ────────────── 9. CRITICAL ALERT BANNER ────────────── */

    function renderCriticalAlert(alert) {
        var el = document.getElementById('criticalAlertBanner');
        if (!el) return;
        if (!alert || !alert.signal || alert.signal === 0) {
            el.className = 'critical-alert critical-alert--clear';
            el.innerHTML = '<span class="critical-alert__icon">&#9679;</span> ' +
                '<span class="critical-alert__text">No active critical threats. System nominal.</span>';
            return;
        }

        var severity = alert.signal > 0.7 ? 'high' : alert.signal > 0.4 ? 'medium' : 'low';
        el.className = 'critical-alert critical-alert--' + severity;
        el.innerHTML = '<span class="critical-alert__icon">&#9888;</span>' +
            '<span class="critical-alert__text">' +
            '<strong>' + escapeHtml(cap(alert.sector)) + '</strong> sector — ' +
            escapeHtml(alert.technique) + ' (' + escapeHtml(alert.technique_id) + ') — ' +
            'Signal: <strong>' + Math.round(alert.signal * 100) + '%</strong> — ' +
            alert.evidence_count + ' evidence items' +
            '</span>';
    }

    /* ────────────── OVERALL STATUS INDICATORS ────────────── */

    function renderOverallStatus(overall) {
        if (!overall) return;
        setText('vizConfidence', Math.round(overall.confidence_pct) + '%');
        setText('vizThreatLevel', (overall.threat_level || 'low').toUpperCase());
        setText('vizThreatScore', Math.round((overall.threat_score || 0) * 100) + '%');
        setText('vizActiveAlerts', overall.active_alerts || 0);
        setText('vizEvidence', overall.total_evidence || 0);
        setText('vizSimStep',
            (overall.sim_status ? overall.sim_status.current_step : 0) + '/' +
            (overall.sim_status ? overall.sim_status.total_steps : 0));
        setText('vizSimSector',
            overall.sim_status ? (overall.sim_status.current_sector || '\u2014') : '\u2014');

        var riskBadge = document.getElementById('vizRiskBadge');
        if (riskBadge) {
            var rl = (overall.risk_level || 'normal').toLowerCase();
            var riskClass = (rl === 'critical' || rl === 'high') ? 'danger' : rl === 'medium' ? 'warning' : 'healthy';
            riskBadge.className = 'viz-risk-badge viz-risk-badge--' + riskClass;
            riskBadge.textContent = (overall.risk_level || 'normal').toUpperCase();
        }
    }

    /* ────────────── MAIN RENDER ────────────── */

    function renderAll(data) {
        if (!data) return;
        renderCriticalAlert(data.critical_alert);
        renderOverallStatus(data.overall);
        renderThreatBar(data.sector_heatmap);
        renderDonut(data.threat_distribution);
        renderConfidenceTrend(data.confidence_trend);
        renderAttackFlow(data.attack_paths, data.dependencies);
        renderSectorRisk(data.sector_risk);
    }

    /* ────────────── POLLING ────────────── */

    function pollViz() {
        fetch('/api/dashboard/v2')
            .then(function (r) { return r.json(); })
            .then(renderAll)
            .catch(function () { /* silent */ });
    }

    /* ────────────── RESIZE ────────────── */

    window.addEventListener('resize', function () {
        Object.keys(instances).forEach(function (k) {
            if (instances[k]) instances[k].resize();
        });
    });

    /* ────────────── INIT ────────────── */

    if (document.getElementById('chartThreatActivity') ||
        document.getElementById('chartThreatDistribution') ||
        document.getElementById('chartConfidenceTrend')) {

        /* Render initial data immediately from injected global */
        if (window.CYBER_VIZ_DATA) {
            renderAll(window.CYBER_VIZ_DATA);
        }

        /* Start live polling */
        setInterval(pollViz, POLL_INTERVAL);
        pollViz();
    }

    console.log('[CYBER ARENA] ECharts dashboard module loaded (Phase 22).');
})();
