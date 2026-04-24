/* ===================================================================
 * ShadowGraph Dashboard — Enterprise Frontend Logic
 * =================================================================== */
(function () {
    'use strict';

    // ----- State -----
    var dsN, dsE, network, nodes = [], edges = [], allExpanded = false, currentScanID = null;
    var currentAnalysis = null;

    // ----- Helpers -----
    function qs(id) { return document.getElementById(id); }
    function qsa(sel) { return Array.prototype.slice.call(document.querySelectorAll(sel)); }

    function escapeHTML(s) {
        return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
            return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
        });
    }

    function fmtNum(n) {
        if (n == null || isNaN(n)) return '0';
        return new Intl.NumberFormat('tr-TR').format(n);
    }

    function safeJSON(s) {
        try { return JSON.parse(s); } catch (e) { return {}; }
    }

    function setText(id, v) {
        var el = qs(id); if (el) el.textContent = (v == null ? '—' : v);
    }

    function nowText() {
        var d = new Date();
        var pad = function (n) { return n < 10 ? '0' + n : '' + n; };
        return pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
    }

    // ----- Toasts -----
    function toast(msg, kind) {
        kind = kind || 'info';
        var iconMap = { ok: 'fa-circle-check', warn: 'fa-triangle-exclamation', err: 'fa-circle-xmark', info: 'fa-circle-info' };
        var box = qs('toasts');
        if (!box) { console.log('[toast]', msg); return; }
        var el = document.createElement('div');
        el.className = 'toast ' + kind;
        el.innerHTML = '<i class="fa-solid ' + iconMap[kind] + '"></i><div>' + escapeHTML(msg) + '</div>';
        box.appendChild(el);
        setTimeout(function () { if (el.parentNode) el.parentNode.removeChild(el); }, 4500);
    }

    // ----- Connection status -----
    function setConn(ok, text) {
        var dot = qs('connStatus');
        var t = qs('connText');
        if (!dot) return;
        dot.classList.toggle('is-down', !ok);
        if (t) t.textContent = text || (ok ? 'CANLI' : 'KESILDI');
    }

    // ----- Scans -----
    async function loadScans() {
        try {
            var resp = await fetch('/api/scans');
            if (!resp.ok) {
                setConn(false, 'API HATA');
                return;
            }
            setConn(true);
            var scans = await resp.json();
            var sel = qs('scanSelect');
            sel.innerHTML = '';
            if (!scans || scans.length === 0) {
                var opt = document.createElement('option');
                opt.value = '';
                opt.textContent = 'Tarama bulunamadı';
                sel.appendChild(opt);
                return;
            }
            scans.forEach(function (s) {
                var opt = document.createElement('option');
                opt.value = s.id;
                var label = '#' + s.id + ' — ' + (s.target || 'bilinmiyor');
                if (s.profile) label += '  [' + s.profile + ']';
                opt.textContent = label;
                sel.appendChild(opt);
            });
            if (currentScanID === null) currentScanID = scans[0].id;
            sel.value = currentScanID;
        } catch (e) {
            setConn(false, 'BAĞLANTI HATASI');
            console.error('scan list:', e);
        }
    }

    // ----- Graph helpers -----
    function hasVulnChild(nid) {
        var ch = edges.filter(function (e) { return e.from === nid; });
        for (var i = 0; i < ch.length; i++) {
            var c = nodes.find(function (n) { return n.id === ch[i].to; });
            if (c && (c.group === 'vulnerability' || c.group === 'exploit')) return true;
            if (c && hasVulnChild(c.id)) return true;
        }
        return false;
    }
    function getChildIds(nid) {
        return edges.filter(function (e) { return e.from === nid; }).map(function (e) { return e.to; });
    }

    // ----- Graph + tables -----
    async function loadGraph() {
        var url = '/api/graph';
        if (currentScanID) url += '?scan_id=' + encodeURIComponent(currentScanID);
        try {
            var resp = await fetch(url);
            if (!resp.ok) { toast('Grafik verisi alınamadı', 'err'); return; }
            var data = await resp.json();
            nodes = data.nodes || [];
            edges = data.edges || [];
        } catch (e) {
            toast('Sunucuya ulaşılamadı', 'err');
            return;
        }

        var targets = nodes.filter(function (n) { return n.group === 'target'; });
        var ports = nodes.filter(function (n) { return n.group === 'port'; });
        var endpoints = nodes.filter(function (n) { return n.group === 'endpoint'; });
        var vulns = nodes.filter(function (n) { return n.group === 'vulnerability'; });
        var exploits = nodes.filter(function (n) { return n.group === 'exploit'; });
        var shields = nodes.filter(function (n) { return n.group === 'shield'; });

        // KPI cards
        setText('sD', fmtNum(targets.length));
        setText('sH', fmtNum(targets.length));
        setText('sP', fmtNum(ports.length));
        setText('sS', fmtNum(endpoints.length));
        setText('sV', fmtNum(vulns.length));
        setText('sE', fmtNum(exploits.length));
        setText('sSH', fmtNum(shields.length));

        var riskCount = vulns.length + exploits.length;
        setText('gR', fmtNum(riskCount));

        // Highlight vuln KPI card if there are findings
        var vulnsCard = document.querySelector('.kpi[data-kpi="vulns"]');
        if (vulnsCard) vulnsCard.classList.toggle('has-vulns', vulns.length > 0);

        // ===== Asset Inventory table =====
        var tb1 = '';
        targets.forEach(function (t) {
            var pd = safeJSON(t.data);
            var os = pd.os_version || '—';
            var ip = pd.ip_address || '—';
            var hn = pd.hostname || (t.label || '').split('\n')[0] || '—';
            var portCount = edges.filter(function (e) { return e.from === t.id; }).length;
            var hasVuln = hasVulnChild(t.id);
            var statusBadge = hasVuln
                ? '<span class="badge b-bad"><i class="fa-solid fa-triangle-exclamation"></i>Riskli</span>'
                : '<span class="badge b-ok"><i class="fa-solid fa-shield-check"></i>Güvenli</span>';
            tb1 += '<tr>'
                + '<td>' + statusBadge + '</td>'
                + '<td><strong>' + escapeHTML(hn) + '</strong></td>'
                + '<td class="mono">' + escapeHTML(ip) + '</td>'
                + '<td>' + escapeHTML(os) + '</td>'
                + '<td class="num">' + fmtNum(portCount) + '</td>'
                + '</tr>';
        });
        var t1Body = document.querySelector('#t1 tbody');
        if (t1Body) t1Body.innerHTML = tb1;
        setText('t1Count', targets.length);
        var t1Empty = qs('t1Empty');
        if (t1Empty) t1Empty.hidden = targets.length > 0;
        var t1Tbl = qs('t1');
        if (t1Tbl) t1Tbl.style.display = targets.length > 0 ? '' : 'none';

        // ===== Findings table =====
        var tb3 = '';
        var t3Total = 0;

        ports.forEach(function (n) {
            var isVuln = hasVulnChild(n.id);
            var portColor = isVuln ? 'var(--danger)' : 'var(--ok)';
            var icon = isVuln
                ? '<i class="fa-solid fa-circle-exclamation" style="color:var(--danger)"></i>'
                : '<i class="fa-solid fa-plug" style="color:var(--ok)"></i>';

            var svcLabel = 'Tespit edildi';
            var childIds = getChildIds(n.id);
            for (var ci = 0; ci < childIds.length; ci++) {
                var cn = nodes.find(function (nd) { return nd.id === childIds[ci]; });
                if (cn && cn.group === 'endpoint') {
                    var epd = safeJSON(cn.data);
                    if (epd.service) svcLabel = epd.service + (epd.version ? ' ' + epd.version : '');
                    break;
                }
            }
            var sevPill = isVuln
                ? '<span class="sev sev-HIGH">RİSKLİ</span>'
                : '<span class="sev sev-LOW">TEMİZ</span>';
            tb3 += '<tr>'
                + '<td>' + icon + ' <strong style="color:' + portColor + '" class="mono">' + escapeHTML(n.label) + '</strong></td>'
                + '<td>' + escapeHTML(svcLabel) + '</td>'
                + '<td>' + sevPill + '</td>'
                + '</tr>';
            t3Total++;
        });

        vulns.forEach(function (n) {
            var pd = safeJSON(n.data);
            var sev = (pd.severity || 'HIGH').toUpperCase();
            var sevClass = 'sev-' + (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].indexOf(sev) >= 0 ? sev : 'NA');
            tb3 += '<tr>'
                + '<td><i class="fa-solid fa-bug" style="color:var(--danger)"></i> <span class="mono" style="color:var(--danger)">CVE</span></td>'
                + '<td><strong>' + escapeHTML(pd.cve || n.label) + '</strong>'
                + (pd.cvss ? ' <span class="mono" style="color:var(--text-muted);font-size:.7rem">· CVSS ' + escapeHTML(pd.cvss) + '</span>' : '')
                + '</td>'
                + '<td><span class="sev ' + sevClass + '">' + escapeHTML(sev) + '</span></td>'
                + '</tr>';
            t3Total++;
        });

        exploits.forEach(function (n) {
            var pd = safeJSON(n.data);
            tb3 += '<tr>'
                + '<td><i class="fa-solid fa-bolt" style="color:var(--purple)"></i> <span class="mono" style="color:var(--purple)">EXP</span></td>'
                + '<td><strong>' + escapeHTML(pd.exploit_id || n.label) + '</strong></td>'
                + '<td><span class="badge b-exp">' + escapeHTML(pd.source || 'EXPLOIT') + '</span></td>'
                + '</tr>';
            t3Total++;
        });

        shields.forEach(function (n) {
            var pd = safeJSON(n.data);
            tb3 += '<tr>'
                + '<td><i class="fa-solid fa-shield" style="color:var(--warn)"></i> <span class="mono" style="color:var(--warn)">WAF</span></td>'
                + '<td>' + escapeHTML(pd.shield_type || n.label) + '</td>'
                + '<td><span class="badge b-shield">CDN/WAF</span></td>'
                + '</tr>';
            t3Total++;
        });

        var t3Body = document.querySelector('#t3 tbody');
        if (t3Body) t3Body.innerHTML = tb3;
        setText('t3Count', t3Total);
        var t3Empty = qs('t3Empty');
        if (t3Empty) t3Empty.hidden = t3Total > 0;
        var t3Tbl = qs('t3');
        if (t3Tbl) t3Tbl.style.display = t3Total > 0 ? '' : 'none';

        // ===== Network visualization =====
        renderNetwork();

        // Last updated meta
        setText('lastUpdatedText', 'Son güncelleme ' + nowText());
    }

    function renderNetwork() {
        var visNodes = nodes.map(function (n) {
            var pd = safeJSON(n.data || '{}');
            var lbl = n.label;
            if (n.group === 'vulnerability' && pd.cve) lbl = pd.cve;
            var isT = n.group === 'target';
            var b = {
                id: n.id, label: lbl, group: n.group, _raw: pd,
                hidden: !isT, _expanded: false,
                _searchLabel: (lbl + ' ' + JSON.stringify(pd)).toLowerCase()
            };
            if (n.group === 'target') {
                b.shape = 'icon'; b.icon = { face: '"Font Awesome 6 Free"', code: '\uf233', weight: 900, size: 50, color: '#06b6d4' };
                b.font = { color: '#06b6d4', size: 14, face: 'Inter' };
            } else if (n.group === 'port') {
                var col = hasVulnChild(n.id) ? '#ef4444' : '#10b981';
                b.shape = 'icon'; b.icon = { face: '"Font Awesome 6 Free"', code: '\uf1e6', weight: 900, size: 30, color: col };
                b.font = { color: col, size: 12, face: 'Inter' };
            } else if (n.group === 'endpoint') {
                b.shape = 'icon'; b.icon = { face: '"Font Awesome 6 Free"', code: '\uf1b3', weight: 900, size: 30, color: '#f59e0b' };
                b.font = { color: '#f59e0b', size: 12, face: 'Inter' };
            } else if (n.group === 'vulnerability') {
                b.shape = 'icon'; b.icon = { face: '"Font Awesome 6 Free"', code: '\uf188', weight: 900, size: 40, color: '#ef4444' };
                b.font = { color: '#ef4444', size: 14, face: 'Inter' };
            } else if (n.group === 'exploit') {
                b.shape = 'icon'; b.icon = { face: '"Font Awesome 6 Free"', code: '\uf0e7', weight: 900, size: 35, color: '#a855f7' };
                b.font = { color: '#a855f7', size: 12, face: 'Inter' };
            } else if (n.group === 'shield') {
                b.shape = 'icon'; b.icon = { face: '"Font Awesome 6 Free"', code: '\uf132', weight: 900, size: 35, color: '#f59e0b' };
                b.font = { color: '#f59e0b', size: 12, face: 'Inter' };
            }
            return b;
        });
        var visEdges = edges.map(function (e) {
            var target = visNodes.find(function (n) { return n.id === e.to; });
            return {
                from: e.from, to: e.to, label: e.label,
                color: { color: 'rgba(6,182,212,.35)', highlight: '#06b6d4' },
                arrows: { to: { enabled: true, scaleFactor: .7 } },
                length: 140,
                hidden: target ? target.hidden : false
            };
        });

        dsN = new vis.DataSet(visNodes);
        dsE = new vis.DataSet(visEdges);

        if (network) network.destroy();
        network = new vis.Network(
            qs('network'),
            { nodes: dsN, edges: dsE },
            {
                nodes: { shadow: { enabled: true, color: 'rgba(0,0,0,0.4)', size: 8 } },
                edges: { smooth: { type: 'continuous', roundness: 0.3 } },
                physics: {
                    solver: 'forceAtlas2Based',
                    forceAtlas2Based: { gravitationalConstant: -65, centralGravity: 0.008, springLength: 150 },
                    stabilization: { iterations: 200 }
                },
                interaction: { hover: true, tooltipDelay: 200, navigationButtons: false }
            }
        );

        network.on('click', function (params) {
            if (params.nodes.length === 0) return;
            var cid = params.nodes[0];
            var cn = dsN.get(cid);
            var chIds = getChildIds(cid);
            if (chIds.length === 0) return;

            var exp = cn._expanded;
            function setVis(ids, v) {
                ids.forEach(function (id) {
                    dsN.update({ id: id, hidden: !v });
                    dsE.get().forEach(function (e) {
                        if (e.to === id || (e.from === id && !v)) dsE.update({ id: e.id, hidden: !v });
                    });
                    if (!v) {
                        var gc = getChildIds(id);
                        setVis(gc, false);
                        dsN.update({ id: id, _expanded: false });
                    }
                });
            }
            setVis(chIds, !exp);
            dsN.update({ id: cid, _expanded: !exp });
        });

        // Reset expand state
        allExpanded = false;
        var exBtn = qs('btnExpand');
        if (exBtn) {
            exBtn.innerHTML = '<i class="fa-solid fa-up-right-and-down-left-from-center"></i><span>Tümünü Aç</span>';
        }
    }

    // ----- AI Analysis -----
    async function loadAIAnalysis() {
        if (!currentScanID) {
            renderAIEmpty('Önce bir tarama seçin.');
            return;
        }
        try {
            var resp = await fetch('/api/analysis?scan_id=' + encodeURIComponent(currentScanID));
            if (resp.status === 404) {
                renderAIEmpty('Bu tarama için henüz analiz yok.');
                return;
            }
            if (!resp.ok) return;
            var a = await resp.json();
            currentAnalysis = a;
            renderAIAnalysis(a);
        } catch (e) {
            console.error('ai load:', e);
        }
    }

    function renderAIEmpty(msg) {
        qs('aiPanel').innerHTML =
            '<div class="empty-state">'
            + '<i class="fa-solid fa-wand-magic-sparkles"></i>'
            + '<div>' + escapeHTML(msg || 'Henüz analiz yapılmadı.') + '</div>'
            + '<div class="empty-hint">"Analiz Et" düğmesi ile saldırı yollarını ve önerileri üretin.</div>'
            + '</div>';
        // Reset gauge
        updateGauge(null, null);
        setText('gCrit', '0');
        setText('gHigh', '0');
        setText('gTotal', '0');
    }

    function renderAIAnalysis(a) {
        if (!a) { renderAIEmpty(); return; }
        var lvl = (a.risk_level || '').toUpperCase();
        var score = (a.overall_risk != null ? a.overall_risk : (a.overall_risk_score != null ? a.overall_risk_score : null));

        // Update gauge & posture meta
        updateGauge(score, lvl);
        setText('gCrit', fmtNum(a.critical_paths || 0));
        setText('gHigh', fmtNum(a.high_risk_paths || 0));
        setText('gTotal', fmtNum(a.total_paths || 0));

        var html = '<div class="ai-shell">';

        // Headline
        html += '<div class="ai-headline">';
        html += '<div class="ai-headline-left">';
        html += '<div class="ai-score"><div class="ai-score-num">' + (score != null ? score.toFixed(1) : '—') + '</div><div class="ai-score-suf">RISK / 10</div></div>';
        if (lvl) html += '<span class="ai-level lvl-' + escapeHTML(lvl) + '">' + escapeHTML(lvl) + '</span>';
        html += '</div>';
        if (a.provider) html += '<span class="ai-provider"><i class="fa-solid fa-microchip"></i> ' + escapeHTML(a.provider) + '</span>';
        html += '</div>';

        // Stats
        html += '<div class="ai-stats">';
        html += '<div class="ai-stat"><div class="ai-stat-val">' + fmtNum(a.total_paths || 0) + '</div><div class="ai-stat-lbl">Toplam Yol</div></div>';
        html += '<div class="ai-stat"><div class="ai-stat-val danger">' + fmtNum(a.critical_paths || 0) + '</div><div class="ai-stat-lbl">Kritik</div></div>';
        html += '<div class="ai-stat"><div class="ai-stat-val warn">' + fmtNum(a.high_risk_paths || 0) + '</div><div class="ai-stat-lbl">Yüksek</div></div>';
        html += '</div>';

        // Summary
        if (a.summary) {
            html += '<div class="ai-section">';
            html += '<h4><i class="fa-solid fa-file-lines"></i>Yönetici Özeti</h4>';
            html += '<div class="ai-summary-text">' + escapeHTML(a.summary) + '</div>';
            html += '</div>';
        }

        // Chained attacks
        var chains = a.chained_attacks || [];
        if (chains.length) {
            html += '<div class="ai-section">';
            html += '<h4><i class="fa-solid fa-link"></i>Zincirleme Saldırı Senaryoları (' + chains.length + ')</h4>';
            html += '<div class="ai-chains">';
            chains.forEach(function (ch) {
                html += '<div class="ai-chain">';
                html += '<div class="ai-chain-name">' + escapeHTML(ch.name) + '<span class="ai-chain-risk">' + (ch.risk_score ? ch.risk_score.toFixed(1) : '—') + '</span></div>';
                if (ch.description) html += '<div class="ai-chain-desc">' + escapeHTML(ch.description) + '</div>';
                if (ch.scenario) html += '<div class="ai-chain-scenario"><i class="fa-solid fa-route"></i> ' + escapeHTML(ch.scenario) + '</div>';
                if (ch.cves && ch.cves.length) {
                    html += '<div class="ai-chain-cves">';
                    ch.cves.forEach(function (c) { html += '<span class="cve-chip">' + escapeHTML(c) + '</span>'; });
                    html += '</div>';
                }
                html += '</div>';
            });
            html += '</div></div>';
        }

        // Top paths
        var paths = a.top_paths || [];
        if (paths.length) {
            html += '<div class="ai-section">';
            html += '<h4><i class="fa-solid fa-route"></i>En Riskli Yollar</h4>';
            html += '<div class="ai-paths">';
            paths.slice(0, 8).forEach(function (p, i) {
                var cls = '';
                if (p.risk_score >= 9) cls = 'crit';
                else if (p.risk_score >= 7) cls = 'high';
                html += '<div class="ai-path">';
                html += '<span class="ai-path-num ' + cls + '">' + (i + 1) + '</span>';
                html += '<span class="ai-path-summary">' + escapeHTML(p.summary || '—') + '</span>';
                html += '<span class="ai-path-risk">' + (p.risk_score != null ? p.risk_score.toFixed(1) : '—') + ' / 10</span>';
                html += '</div>';
            });
            html += '</div></div>';
        }

        // Recommendations
        var recs = a.recommendations || [];
        if (recs.length) {
            html += '<div class="ai-section">';
            html += '<h4><i class="fa-solid fa-list-check"></i>Öneriler (' + recs.length + ')</h4>';
            html += '<ul class="ai-recs">';
            recs.forEach(function (r) {
                var urgent = /ACİL|CRITICAL|KRITIK/i.test(r);
                html += '<li' + (urgent ? ' class="urgent"' : '') + '>'
                    + '<i class="fa-solid ' + (urgent ? 'fa-circle-exclamation' : 'fa-arrow-right') + '"></i>'
                    + '<span>' + escapeHTML(r) + '</span>'
                    + '</li>';
            });
            html += '</ul></div>';
        }

        html += '</div>';
        qs('aiPanel').innerHTML = html;
    }

    // ----- Risk Gauge SVG -----
    function updateGauge(score, level) {
        var fill = qs('gaugeFill');
        var needle = qs('gaugeNeedle');
        var gauge = qs('riskGauge');
        var lvlEl = qs('gaugeLevel');

        if (score == null) {
            setText('gH', '—');
            if (fill) fill.setAttribute('stroke-dashoffset', 251.3);
            if (needle) needle.setAttribute('transform', 'rotate(-90 100 110)');
            if (gauge) gauge.setAttribute('data-level', 'info');
            if (lvlEl) lvlEl.textContent = 'BEKLENİYOR';
            return;
        }

        var s = Math.max(0, Math.min(10, score));
        setText('gH', s.toFixed(1));

        // Arc length total ~ 251.3 (half circle radius 80)
        var total = 251.3;
        var pct = s / 10;
        var offset = total * (1 - pct);
        if (fill) fill.setAttribute('stroke-dashoffset', offset);

        // Needle: -90deg (left) to +90deg (right) covering 180deg span
        var deg = -90 + (180 * pct);
        if (needle) needle.setAttribute('transform', 'rotate(' + deg + ' 100 110)');

        if (gauge) gauge.setAttribute('data-level', level || 'MEDIUM');
        if (lvlEl) lvlEl.textContent = level || '—';
    }

    // ----- Run analysis -----
    async function runAnalysis() {
        if (!currentScanID) {
            toast('Önce bir tarama seçin.', 'warn');
            return;
        }
        var btn = qs('btnAnalyze');
        var origHTML = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i><span>Çalışıyor…</span>';
        qs('aiPanel').innerHTML = '<div class="empty-state"><i class="fa-solid fa-spinner fa-spin"></i><div>AI analiz çalışıyor…</div><div class="empty-hint">Saldırı yolları, zincirleme senaryolar ve öneriler hesaplanıyor.</div></div>';
        try {
            var resp = await fetch('/api/analyze', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ scan_id: Number(currentScanID) })
            });
            if (!resp.ok) {
                var txt = await resp.text();
                renderAIEmpty('Analiz başarısız: ' + txt);
                toast('Analiz başarısız', 'err');
                return;
            }
            var a = await resp.json();
            currentAnalysis = a;
            renderAIAnalysis(a);
            toast('Analiz tamamlandı', 'ok');
        } catch (e) {
            renderAIEmpty('Hata: ' + (e.message || e));
            toast('Sunucu hatası', 'err');
        } finally {
            btn.disabled = false;
            btn.innerHTML = origHTML;
        }
    }

    // ----- Bind events -----
    function bindEvents() {
        qs('btnShare').addEventListener('click', function () {
            navigator.clipboard.writeText(window.location.href).then(
                function () { toast('Bağlantı panoya kopyalandı', 'ok'); },
                function () { toast('Kopyalama başarısız', 'err'); }
            );
        });

        qs('btnExport').addEventListener('click', function () {
            // Inject print metadata so the print header can show date
            try {
                var d = new Date();
                var iso = d.toLocaleDateString('tr-TR') + ' ' + d.toLocaleTimeString('tr-TR');
                var bar = document.querySelector('.appbar');
                if (bar) bar.setAttribute('data-print-date', iso);
            } catch (e) {}
            window.print();
        });

        qs('btnRefresh').addEventListener('click', async function () {
            this.classList.add('spinning');
            await loadScans();
            await loadGraph();
            await loadAIAnalysis();
            this.classList.remove('spinning');
            toast('Veriler yenilendi', 'ok');
        });

        qs('btnAnalyze').addEventListener('click', runAnalysis);

        qs('scanSelect').addEventListener('change', async function () {
            currentScanID = this.value || null;
            await loadGraph();
            await loadAIAnalysis();
        });

        qs('btnExpand').addEventListener('click', function () {
            allExpanded = !allExpanded;
            if (!dsN) return;
            dsN.get().forEach(function (n) {
                if (n.group !== 'target') {
                    dsN.update({ id: n.id, hidden: !allExpanded, _expanded: allExpanded });
                }
            });
            dsE.get().forEach(function (e) { dsE.update({ id: e.id, hidden: !allExpanded }); });
            this.innerHTML = allExpanded
                ? '<i class="fa-solid fa-down-left-and-up-right-to-center"></i><span>Tümünü Kapat</span>'
                : '<i class="fa-solid fa-up-right-and-down-left-from-center"></i><span>Tümünü Aç</span>';
        });

        var sb = qs('searchBox');
        var sbTimer;
        sb.addEventListener('input', function () {
            clearTimeout(sbTimer);
            var v = this.value.toLowerCase();
            sbTimer = setTimeout(function () {
                if (!dsN) return;
                dsN.get().forEach(function (n) {
                    if (n.group === 'target') { dsN.update({ id: n.id, hidden: false }); return; }
                    if (!v) { dsN.update({ id: n.id, hidden: !allExpanded }); return; }
                    var match = n._searchLabel && n._searchLabel.indexOf(v) !== -1;
                    dsN.update({ id: n.id, hidden: !match });
                    dsE.get().forEach(function (e) { if (e.to === n.id) dsE.update({ id: e.id, hidden: !match }); });
                });
            }, 120);
        });

        qsa('.fbtn').forEach(function (btn) {
            btn.addEventListener('click', function () {
                qsa('.fbtn').forEach(function (b) { b.classList.remove('active'); });
                this.classList.add('active');
                var filter = this.dataset.filter;
                if (!dsN) return;
                dsN.get().forEach(function (n) {
                    if (n.group === 'target') { dsN.update({ id: n.id, hidden: false }); return; }
                    if (filter === 'all') { dsN.update({ id: n.id, hidden: !allExpanded }); return; }
                    var show = n.group === filter;
                    dsN.update({ id: n.id, hidden: !show });
                    dsE.get().forEach(function (e) { if (e.to === n.id || e.from === n.id) dsE.update({ id: e.id, hidden: !show }); });
                });
            });
        });

        // Auto-refresh status check every 30s
        setInterval(async function () {
            try {
                var r = await fetch('/api/scans');
                setConn(r.ok);
            } catch (e) { setConn(false); }
        }, 30000);
    }

    // ----- Init -----
    (async function init() {
        bindEvents();
        await loadScans();
        await loadGraph();
        await loadAIAnalysis();
    })();
})();
