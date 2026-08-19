(() => {
  const data = window.HACKUITY_DATA || { assets: [], criticalFindings: [], cves: [], remediations: [] };
  const $ = (selector) => document.querySelector(selector);
  const $$ = (selector) => [...document.querySelectorAll(selector)];
  const fmt = new Intl.NumberFormat("fr-FR");
  const text = (value, fallback = "—") => value === null || value === undefined || value === "" ? fallback : String(value);
  const number = (value) => Number(value) || 0;
  const risk = (score) => score >= 900 ? "critical" : score >= 700 ? "high" : score >= 400 ? "medium" : "low";
  const riskLabel = (score) => ({ critical: "Critique", high: "Élevé", medium: "Modéré", low: "Faible" })[risk(score)];
  const esc = (value) => text(value, "").replace(/[&<>"']/g, char => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[char]));
  let search = "";
  let selectedServer = data.assets[0]?.assetId || "";
  const scope = { perimeter: "", provider: "", risk: "", kev: false };

  function scopedAssets() {
    return data.assets.filter(asset =>
      (!scope.perimeter || (asset.perimeterIds || []).includes(scope.perimeter)) &&
      (!scope.provider || (asset.providerIds || []).includes(scope.provider)) &&
      (!scope.risk || risk(asset.maxFindingTrs) === scope.risk) &&
      (!scope.kev || number(asset.cisaKevFindings) > 0)
    );
  }

  function scopedFindings() {
    const ids = new Set(scopedAssets().map(asset => asset.assetId));
    return data.criticalFindings.filter(item => ids.has(item.assetId));
  }

  function scopedCves() {
    if (!scope.perimeter && !scope.provider && !scope.risk && !scope.kev) return data.cves;
    const ids = new Set(scopedFindings().flatMap(item => String(item.cve || "").split(/[,;\s]+/).filter(x => /^CVE-/i.test(x))));
    return data.cves.filter(item => ids.has(item.cveId));
  }

  function setView(id) {
    $$(".view").forEach(view => view.classList.toggle("active", view.id === id));
    $$(".nav-item").forEach(item => item.classList.toggle("active", item.dataset.view === id));
    const label = $(`.nav-item[data-view="${id}"]`)?.textContent.trim() || "Dashboard";
    $("#pageTitle").textContent = label;
    renderAll();
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  function matches(row) {
    if (!search) return true;
    return Object.values(row).some(value => String(value ?? "").toLowerCase().includes(search));
  }

  function badge(value) {
    const normalized = String(value || "N/A").toLowerCase();
    const kind = normalized.includes("critical") ? "critical" : normalized.includes("high") ? "high" : normalized.includes("medium") ? "medium" : normalized.includes("p1") ? "p1" : normalized.includes("p2") ? "p2" : normalized.includes("p3") ? "p3" : "low";
    return `<span class="badge ${kind}">${esc(value || "N/A")}</span>`;
  }

  function renderKpis() {
    const assets = scopedAssets(), findings = scopedFindings(), cves = scopedCves();
    const criticalAssets = assets.filter(asset => number(asset.criticalFindings) > 0).length;
    const maxTrs = Math.max(0, ...assets.map(asset => number(asset.maxFindingTrs)));
    $("#kpiAssets").textContent = fmt.format(assets.length);
    $("#kpiAssetsMeta").textContent = `${criticalAssets} avec risque critique`;
    $("#kpiCritical").textContent = fmt.format(findings.length);
    $("#kpiCves").textContent = fmt.format(cves.length);
    $("#kpiCvesMeta").textContent = `${fmt.format(cves.filter(cve => number(cve.maxCvss) >= 9).length)} avec CVSS ≥ 9`;
    $("#kpiRemediations").textContent = fmt.format(data.remediations.length);
    $("#kpiRemediationMeta").textContent = `${fmt.format(data.remediations.filter(item => item.priority === "P1").length)} actions P1`;
    $("#riskScore").textContent = Math.round(maxTrs);
    $("#riskLabel").textContent = riskLabel(maxTrs);
    $("#scoreRing").style.setProperty("--score-angle", `${Math.min(360, maxTrs / 1000 * 360)}deg`);
    $("#dataSource").textContent = `${data.assets.length} assets · ${data.generatedAt?.slice(0, 10) || "démo"}`;
    $("#scopeAssetCount").textContent = fmt.format(assets.length);
    const kev = assets.reduce((sum, asset) => sum + number(asset.cisaKevFindings), 0);
    const withoutIp = assets.filter(asset => !asset.ipAddress).length;
    const oldest = Math.max(0, ...assets.map(asset => number(asset.oldestFindingDays)));
    $("#insightStrip").innerHTML = `
      <div class="insight urgent"><span>⚡</span><div><strong>${fmt.format(kev)} signaux CISA KEV dans le périmètre courant</strong><small>À traiter en priorité car l’exploitation est connue publiquement.</small></div></div>
      <div class="insight warning"><span>◷</span><div><strong>Ancienneté maximale : ${fmt.format(oldest)} jours</strong><small>Les vulnérabilités anciennes augmentent le risque de dette durable.</small></div></div>
      <div class="insight info"><span>◉</span><div><strong>${fmt.format(withoutIp)} assets sans adresse IP consolidée</strong><small>Compléter l’inventaire améliore le routage des remédiations.</small></div></div>`;
  }

  function drawRiskChart() {
    const canvas = $("#riskChart");
    const box = canvas.getBoundingClientRect();
    const ratio = devicePixelRatio || 1;
    canvas.width = box.width * ratio; canvas.height = box.height * ratio;
    const ctx = canvas.getContext("2d"); ctx.scale(ratio, ratio);
    const assets = scopedAssets();
    const buckets = [
      ["Faible", assets.filter(a => number(a.maxFindingTrs) < 400).length, "#30d69b"],
      ["Modéré", assets.filter(a => number(a.maxFindingTrs) >= 400 && number(a.maxFindingTrs) < 700).length, "#ffe06a"],
      ["Élevé", assets.filter(a => number(a.maxFindingTrs) >= 700 && number(a.maxFindingTrs) < 900).length, "#ff9d42"],
      ["Critique", assets.filter(a => number(a.maxFindingTrs) >= 900).length, "#ff5263"],
    ];
    const w = box.width, h = box.height, pad = 34, max = Math.max(1, ...buckets.map(x => x[1]));
    ctx.font = "11px system-ui"; ctx.textAlign = "center";
    buckets.forEach((bucket, index) => {
      const slot = (w - pad * 2) / buckets.length, barW = Math.min(64, slot * .55);
      const x = pad + slot * index + (slot - barW) / 2, barH = (h - 66) * bucket[1] / max, y = h - 38 - barH;
      const gradient = ctx.createLinearGradient(0, y, 0, h); gradient.addColorStop(0, bucket[2]); gradient.addColorStop(1, `${bucket[2]}33`);
      ctx.fillStyle = gradient; ctx.beginPath(); ctx.roundRect(x, y, barW, barH, 7); ctx.fill();
      ctx.fillStyle = bucket[2]; ctx.font = "700 13px system-ui"; ctx.fillText(bucket[1], x + barW / 2, y - 8);
      ctx.fillStyle = getComputedStyle(document.body).getPropertyValue("--muted"); ctx.font = "10px system-ui"; ctx.fillText(bucket[0], x + barW / 2, h - 14);
    });
  }

  function drawSeverityChart() {
    const counts = {};
    scopedFindings().forEach(item => counts[item.severity || "Non classé"] = (counts[item.severity || "Non classé"] || 0) + 1);
    const entries = Object.entries(counts).sort((a,b) => b[1]-a[1]).slice(0,5);
    const colors = ["#ff5263","#ff9d42","#7765ff","#4aa9ff","#30d69b"];
    const canvas = $("#severityChart"), ctx = canvas.getContext("2d"), total = Math.max(1, entries.reduce((sum,x)=>sum+x[1],0));
    ctx.clearRect(0,0,canvas.width,canvas.height); let angle = -Math.PI / 2;
    entries.forEach((entry,index) => { const part = entry[1]/total*Math.PI*2; ctx.beginPath();ctx.arc(90,90,67,angle,angle+part);ctx.strokeStyle=colors[index];ctx.lineWidth=20;ctx.stroke();angle+=part; });
    ctx.fillStyle=getComputedStyle(document.body).getPropertyValue("--text");ctx.font="800 26px system-ui";ctx.textAlign="center";ctx.fillText(total,90,87);ctx.fillStyle=getComputedStyle(document.body).getPropertyValue("--muted");ctx.font="9px system-ui";ctx.fillText("FINDINGS",90,104);
    $("#severityLegend").innerHTML = entries.map((entry,index)=>`<div class="legend-row"><i style="background:${colors[index]}"></i><span>${esc(entry[0])}</span><strong>${entry[1]}</strong></div>`).join("");
  }

  function renderOverview() {
    const assets = [...scopedAssets()].sort((a,b)=>number(b.maxFindingTrs)-number(a.maxFindingTrs)).slice(0,6);
    $("#topAssetsBody").innerHTML = assets.map(asset => `<tr><td><strong>${esc(asset.hostname)}</strong><small>${esc(asset.ipAddress)}</small></td><td>${esc(asset.assetOsPrimary)}</td><td>${fmt.format(number(asset.openFindings))}</td><td>${fmt.format(number(asset.criticalFindings))}</td><td class="score ${risk(asset.maxFindingTrs)}">${Math.round(number(asset.maxFindingTrs))}</td><td>${badge(riskLabel(asset.maxFindingTrs))}</td></tr>`).join("");
    $("#remediationActions").innerHTML = [...data.remediations].sort((a,b)=>number(b.maxTrs)-number(a.maxTrs)).slice(0,4).map(item => `<div class="action"><div class="action-meta">${badge(item.priority)}<span>${fmt.format(number(item.affectedAssets))} assets</span></div><p>${esc(item.remediation)}</p><div class="action-meta"><span>TRS ${Math.round(number(item.maxTrs))}</span><span>${fmt.format(number(item.findingCount))} findings</span></div></div>`).join("");
    requestAnimationFrame(() => { drawRiskChart(); drawSeverityChart(); });
  }

  function serverFindings(asset) {
    return data.criticalFindings.filter(item =>
      item.assetId === asset?.assetId ||
      (asset?.hostname && item.hostname === asset.hostname)
    );
  }

  function relatedRemediations(findings) {
    const findingText = findings.map(item => `${item.remediation || ""} ${item.cve || ""}`).join(" ").toLowerCase();
    const directlyRelated = data.remediations.filter(item => {
      const remediation = String(item.remediation || "").toLowerCase();
      return remediation.length > 20 && findingText.includes(remediation.slice(0, 45));
    });
    return (directlyRelated.length ? directlyRelated : data.remediations)
      .sort((a,b) => number(b.maxTrs) - number(a.maxTrs)).slice(0, 5);
  }

  function drawServerGauge(score) {
    const canvas = $("#serverGauge"), ctx = canvas.getContext("2d");
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    const cx = 140, cy = 142, radius = 102, start = Math.PI, end = Math.PI * 2;
    ctx.lineWidth = 22; ctx.lineCap = "round";
    ctx.beginPath(); ctx.arc(cx, cy, radius, start, end); ctx.strokeStyle = "#252c3c"; ctx.stroke();
    const gradient = ctx.createLinearGradient(38, 0, 242, 0);
    gradient.addColorStop(0, "#30d69b"); gradient.addColorStop(.5, "#ff9d42"); gradient.addColorStop(1, "#ff5263");
    ctx.beginPath(); ctx.arc(cx, cy, radius, start, start + Math.PI * Math.min(1, number(score) / 1000)); ctx.strokeStyle = gradient; ctx.stroke();
    ctx.fillStyle = getComputedStyle(document.body).getPropertyValue("--text");
    ctx.textAlign = "center"; ctx.font = "800 34px system-ui"; ctx.fillText(Math.round(number(score)), cx, 126);
    ctx.fillStyle = getComputedStyle(document.body).getPropertyValue("--muted"); ctx.font = "9px system-ui"; ctx.fillText("TRS / 1000", cx, 145);
  }

  function renderServer() {
    const available = scopedAssets();
    const asset = available.find(item => item.assetId === selectedServer) || available[0] || data.assets[0];
    if (!asset) return;
    selectedServer = asset.assetId;
    const severity = $("#serverSeverityFilter").value;
    const query = $("#serverFindingSearch").value.trim().toLowerCase();
    const allFindings = serverFindings(asset);
    const findings = allFindings.filter(item =>
      (!severity || item.severity === severity) &&
      (!query || Object.values(item).some(value => String(value ?? "").toLowerCase().includes(query)))
    ).sort((a,b) => number(b.hyScoreV2) - number(a.hyScoreV2));
    $("#serverHostname").textContent = text(asset.hostname);
    $("#serverIp").textContent = text(asset.ipAddress, "IP non renseignée");
    $("#serverOs").textContent = text(asset.assetOsPrimary, "OS non renseigné");
    $("#serverRiskBadge").innerHTML = badge(riskLabel(asset.maxFindingTrs));
    $("#serverTrs").textContent = Math.round(number(asset.maxFindingTrs));
    $("#serverOpen").textContent = fmt.format(number(asset.openFindings));
    $("#serverCritical").textContent = fmt.format(number(asset.criticalFindings));
    $("#serverCvss").textContent = number(asset.maxCvss).toFixed(1);
    $("#serverAge").textContent = asset.oldestFindingDays ? `${fmt.format(number(asset.oldestFindingDays))} j` : "—";
    $("#serverFindingsBody").innerHTML = findings.map(item => `<tr><td><strong>${esc(item.findingName || item.findingId)}</strong><small>${esc(item.findingId)}</small></td><td>${esc(item.cve)}</td><td>${badge(item.severity)}</td><td class="score ${risk(item.hyScoreV2)}">${Math.round(number(item.hyScoreV2))}</td><td>${number(item.cvssScore).toFixed(1)}</td><td>${esc(item.provider)}</td><td>${esc(item.lastSeen?.slice(0,10))}</td></tr>`).join("");
    $("#serverFindingsEmpty").style.display = findings.length ? "none" : "block";
    $("#serverDetails").innerHTML = [
      ["Asset ID", asset.assetId], ["Hostname", asset.hostname], ["Adresse IP", asset.ipAddress],
      ["Système", asset.assetOsPrimary], ["Provider", asset.provider], ["Pays", asset.country],
      ["Business Unit", asset.businessUnit], ["Top CVE", asset.topCve], ["Dernière observation", asset.lastSeen?.slice(0, 10)]
    ].map(([label,value]) => `<div><dt>${label}</dt><dd>${esc(value)}</dd></div>`).join("");
    $("#serverRemediations").innerHTML = relatedRemediations(allFindings).map(item => `<div class="server-remediation">${badge(item.priority)}<p><strong>${esc(item.remediation)}</strong><small>${esc(item.priorityReason, "Priorité calculée selon le risque observé")} · délai cible ${number(item.dueInDays)} j · ${item.remediationSource === "derived" ? "action dérivée" : "action source"}</small></p><small>${fmt.format(number(item.affectedAssets))} assets<br>TRS ${Math.round(number(item.maxTrs))}</small></div>`).join("");
    $("#serverGaugeText").textContent = `${riskLabel(asset.maxFindingTrs)} · ${number(asset.criticalFindings)} findings critiques`;
    requestAnimationFrame(() => drawServerGauge(asset.maxFindingTrs));
  }

  function openServer(assetId) {
    selectedServer = assetId;
    $("#serverSelect").value = assetId;
    setView("servers");
  }

  function openDrawer(assetId) {
    const asset = data.assets.find(item => item.assetId === assetId);
    if (!asset) return;
    const findings = serverFindings(asset).sort((a,b)=>number(b.hyScoreV2)-number(a.hyScoreV2));
    $("#drawerContent").innerHTML = `<div class="drawer-hero"><p class="eyebrow">SERVER PROFILE</p><h2>${esc(asset.hostname)}</h2><p>${esc(asset.ipAddress)} · ${esc(asset.assetOsPrimary)}</p>${badge(riskLabel(asset.maxFindingTrs))}</div>
      <div class="server-kpis"><div><small>TRS</small><strong>${Math.round(number(asset.maxFindingTrs))}</strong></div><div><small>OUVERTS</small><strong>${fmt.format(number(asset.openFindings))}</strong></div><div><small>CRITIQUES</small><strong>${fmt.format(number(asset.criticalFindings))}</strong></div></div>
      <div class="drawer-section"><h3>Findings critiques</h3>${findings.slice(0,8).map(item=>`<div class="drawer-finding"><strong>${esc(item.findingName || item.cve || item.findingId)}</strong><small>${esc(item.cve)} · TRS ${Math.round(number(item.hyScoreV2))} · CVSS ${number(item.cvssScore).toFixed(1)}</small></div>`).join("") || '<p class="result-count">Aucun finding critique dans l’échantillon.</p>'}</div>
      <div class="drawer-section"><button class="open-server" data-drawer-server="${esc(asset.assetId)}">Ouvrir l’analyse complète →</button></div>`;
    $("#detailDrawer").classList.add("open"); $("#drawerBackdrop").classList.add("open"); $("#detailDrawer").setAttribute("aria-hidden","false");
    $("[data-drawer-server]")?.addEventListener("click", () => { closeDrawer(); openServer(assetId); });
  }

  function closeDrawer() {
    $("#detailDrawer").classList.remove("open"); $("#drawerBackdrop").classList.remove("open"); $("#detailDrawer").setAttribute("aria-hidden","true");
  }

  function renderAssets() {
    const filter = $("#assetRiskFilter").value, os = $("#assetOsFilter").value;
    const minimum = number($("#assetMinFindings").value), sort = $("#assetSort").value;
    const rows = scopedAssets().filter(asset => matches(asset) && (!filter || risk(asset.maxFindingTrs) === filter) && (!os || asset.assetOsPrimary === os) && number(asset.openFindings) >= minimum);
    rows.sort((a,b) => sort === "findings" ? number(b.openFindings)-number(a.openFindings) : sort === "critical" ? number(b.criticalFindings)-number(a.criticalFindings) : sort === "hostname" ? String(a.hostname).localeCompare(String(b.hostname)) : number(b.maxFindingTrs)-number(a.maxFindingTrs));
    $("#assetCount").textContent = `${fmt.format(rows.length)} assets`;
    $("#assetsBody").innerHTML = rows.map(asset => `<tr data-server="${esc(asset.assetId)}"><td><strong>${esc(asset.hostname)}</strong><small>${esc(asset.assetId)}</small></td><td>${esc(asset.ipAddress)}</td><td>${esc(asset.assetOsPrimary)}</td><td>${fmt.format(number(asset.openFindings))}</td><td>${fmt.format(number(asset.criticalFindings))}</td><td>${esc(asset.topCve)}</td><td class="score ${risk(asset.maxFindingTrs)}">${Math.round(number(asset.maxFindingTrs))}</td><td>${esc(asset.lastSeen?.slice(0,10))}</td><td><button class="open-server" data-open="${esc(asset.assetId)}">Analyser</button></td></tr>`).join("");
    $$("[data-open]").forEach(button => button.addEventListener("click", event => { event.stopPropagation(); openServer(button.dataset.open); }));
    $$("tr[data-server]").forEach(row => row.addEventListener("click", () => openDrawer(row.dataset.server)));
  }

  function renderFindings() {
    const server = $("#findingServerFilter").value, severity = $("#findingSeverityFilter").value, provider = $("#findingProviderFilter").value, min = number($("#findingMinTrs").value);
    const rows = scopedFindings().filter(item => matches(item) && (!server || item.assetId === server) && (!severity || item.severity === severity) && (!provider || item.provider === provider) && number(item.hyScoreV2) >= min).sort((a,b)=>number(b.hyScoreV2)-number(a.hyScoreV2));
    $("#findingCount").textContent = `${fmt.format(rows.length)} findings`;
    $("#findingsBody").innerHTML = rows.map(item => `<tr><td><strong>${esc(item.findingName || item.findingId)}</strong><small>${esc(item.findingId)}</small></td><td>${esc(item.hostname)}</td><td>${esc(item.cve)}</td><td>${badge(item.severity)}</td><td class="score critical">${Math.round(number(item.hyScoreV2))}</td><td>${number(item.cvssScore).toFixed(1)}</td><td>${esc(item.provider)}</td><td>${badge(item.status)}</td></tr>`).join("");
  }

  function renderCves() {
    const severity = $("#cveSeverityFilter").value, sort = $("#cveSort").value, minCvss = number($("#cveMinCvss").value), minAssets = number($("#cveMinAssets").value);
    const key = sort === "assets" ? "affectedAssets" : sort === "cvss" ? "maxCvss" : "maxTrs";
    const rows = scopedCves().filter(item => matches(item) && (!severity || item.severity === severity) && number(item.maxCvss) >= minCvss && number(item.affectedAssets) >= minAssets).sort((a,b)=>number(b[key])-number(a[key]));
    $("#cveCount").textContent = `${fmt.format(rows.length)} CVE`;
    $("#cveCards").innerHTML = rows.slice(0,250).map(item => `<article class="data-card"><div class="data-card-head"><h3>${esc(item.cveId)}</h3>${badge(item.priority)} ${badge(item.severity)}</div><p>${esc(item.remediation)}</p><small class="action-rationale">${item.remediationSource === "derived" ? "Action dérivée faute de recommandation source" : "Recommandation fournie par la source"} · délai cible ${number(item.dueInDays)} j</small><div class="data-card-grid"><div class="metric"><small>ASSETS</small><strong>${fmt.format(number(item.affectedAssets))}</strong></div><div class="metric"><small>TRS MAX</small><strong class="score ${risk(item.maxTrs)}">${Math.round(number(item.maxTrs))}</strong></div><div class="metric"><small>CVSS</small><strong>${item.maxCvss == null ? "Non renseigné" : number(item.maxCvss).toFixed(1)}</strong></div></div></article>`).join("");
  }

  function renderRemediations() {
    const priority = $("#priorityFilter").value;
    const rows = data.remediations.filter(item => matches(item) && (!priority || item.priority === priority)).sort((a,b)=>number(b.maxTrs)-number(a.maxTrs));
    $("#remediationCount").textContent = `${fmt.format(rows.length)} actions`;
    $("#remediationCards").innerHTML = rows.slice(0,250).map(item => `<article class="data-card"><div class="data-card-head"><h3>${esc(item.component || "Plan de remédiation")}</h3>${badge(item.priority)}</div><p>${esc(item.remediation)}</p><small class="action-rationale">${esc(item.priorityReason)} · score ${number(item.priorityScore)}/100 · délai cible ${number(item.dueInDays)} j · ${item.remediationSource === "derived" ? "dérivée" : "source"}</small><div class="data-card-grid"><div class="metric"><small>ASSETS</small><strong>${fmt.format(number(item.affectedAssets))}</strong></div><div class="metric"><small>FINDINGS</small><strong>${fmt.format(number(item.findingCount))}</strong></div><div class="metric"><small>TRS MAX</small><strong class="score ${risk(item.maxTrs)}">${Math.round(number(item.maxTrs))}</strong></div></div></article>`).join("");
  }

  function formatBytes(bytes) {
    const units = ["o", "Ko", "Mo", "Go", "To"];
    let value = number(bytes), unit = 0;
    while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit++; }
    return (value >= 10 || unit === 0 ? value.toFixed(0) : value.toFixed(1)) + " " + units[unit];
  }

  function renderCatalog() {
    const catalog = data.catalog || [];
    const query = ($("#catalogSearch")?.value || "").trim().toLowerCase();
    const layer = $("#catalogLayer")?.value || "";
    const rows = catalog.filter(file => (!layer || file.layer === layer) && (!query || (file.name + " " + file.path + " " + (file.fields || []).map(field => field.name).join(" ")).toLowerCase().includes(query)));
    if (!$("#catalogList")) return;
    $("#catalogFiles").textContent = fmt.format(catalog.length);
    $("#catalogRows").textContent = fmt.format(catalog.reduce((sum, file) => sum + number(file.rows), 0));
    $("#catalogSize").textContent = formatBytes(catalog.reduce((sum, file) => sum + number(file.sizeBytes), 0));
    $("#catalogCount").textContent = fmt.format(rows.length) + " fichiers documentés";
    $("#catalogList").innerHTML = rows.map(file => '<details class="catalog-file"><summary><span class="layer-tag ' + esc(file.layer) + '">' + esc(file.layer) + '</span><div><strong>' + esc(file.name) + '</strong><code>' + esc(file.path) + '</code></div><div class="file-meta"><span>' + esc(file.format) + '</span><span>' + formatBytes(file.sizeBytes) + '</span><span>' + (file.rows === null ? "—" : fmt.format(file.rows) + " lignes") + '</span><span>' + (file.fields || []).length + ' champs</span></div><b>⌄</b></summary><div class="schema-wrap">' + ((file.fields || []).length ? '<table><thead><tr><th>Champ</th><th>Type</th><th>Nullable</th><th>Chemin logique</th></tr></thead><tbody>' + file.fields.map(field => '<tr><td><strong>' + esc(field.name) + '</strong></td><td><code>' + esc(field.type) + '</code></td><td>' + (field.nullable ? "Oui" : "Non") + '</td><td><code>' + esc(file.path) + ' → ' + esc(field.name) + '</code></td></tr>').join("") + '</tbody></table>' : '<p>Le schéma détaillé n’est pas extrait pour le format ' + esc(file.format) + ' afin de ne pas charger le fichier complet dans le navigateur.</p>') + '</div></details>').join("") || '<div class="empty-state catalog-empty">Aucun fichier ne correspond à cette recherche.</div>';
  }

  function renderAll() { renderKpis(); renderOverview(); renderServer(); renderAssets(); renderFindings(); renderCves(); renderRemediations(); renderCatalog(); }
  function uniqueOptions(selector, values) { $(selector).insertAdjacentHTML("beforeend", [...new Set(values.filter(Boolean))].sort().map(value=>`<option value="${esc(value)}">${esc(value)}</option>`).join("")); }
  function refreshServerOptions() {
    const assets = scopedAssets().slice().sort((a,b)=>String(a.hostname).localeCompare(String(b.hostname)));
    $("#serverSelect").innerHTML = assets.map(asset=>`<option value="${esc(asset.assetId)}">${esc(asset.hostname)} · TRS ${Math.round(number(asset.maxFindingTrs))}</option>`).join("");
    if (!assets.some(asset => asset.assetId === selectedServer)) selectedServer = assets[0]?.assetId || "";
    $("#serverSelect").value = selectedServer;
  }
  function applyScope() {
    scope.perimeter = $("#globalPerimeter").value;
    scope.provider = $("#globalProvider").value;
    scope.risk = $("#globalRisk").value;
    scope.kev = $("#globalKev").checked;
    refreshServerOptions();
    renderAll();
  }
  function resetScope() {
    $("#globalPerimeter").value = ""; $("#globalProvider").value = "";
    $("#globalRisk").value = ""; $("#globalKev").checked = false;
    $$(".smart-presets button").forEach(button => button.classList.toggle("active", button.dataset.preset === "all"));
    applyScope();
  }
  function usePreset(name) {
    $("#globalPerimeter").value = ""; $("#globalProvider").value = "";
    $("#globalRisk").value = ""; $("#globalKev").checked = false;
    if (name === "critical") $("#globalRisk").value = "critical";
    if (name === "kev") $("#globalKev").checked = true;
    if (name === "qualys") $("#globalProvider").value = "QUALYS_VM";
    if (name === "crowdstrike") $("#globalProvider").value = "CROWDSTRIKE_FALCON";
    $$(".smart-presets button").forEach(button => button.classList.toggle("active", button.dataset.preset === name));
    applyScope();
  }

  $$(".nav-item").forEach(button => button.addEventListener("click", () => setView(button.dataset.view)));
  $$("[data-go]").forEach(button => button.addEventListener("click", () => setView(button.dataset.go)));
  ["assetRiskFilter","assetOsFilter","assetMinFindings","assetSort","findingServerFilter","findingSeverityFilter","findingProviderFilter","findingMinTrs","cveSeverityFilter","cveMinCvss","cveMinAssets","cveSort","priorityFilter","serverSeverityFilter","serverFindingSearch"].forEach(id => $(`#${id}`).addEventListener("input", renderAll));
  ["catalogSearch","catalogLayer"].forEach(id => document.getElementById(id)?.addEventListener("input", renderCatalog));
  $("#serverSelect").addEventListener("change", event => { selectedServer = event.target.value; renderServer(); });
  ["globalPerimeter","globalProvider","globalRisk","globalKev"].forEach(id => $(`#${id}`).addEventListener("change", () => {
    $$(".smart-presets button").forEach(button => button.classList.remove("active")); applyScope();
  }));
  $("#resetFilters").addEventListener("click", resetScope);
  $$("[data-preset]").forEach(button => button.addEventListener("click", () => usePreset(button.dataset.preset)));
  $("#drawerClose").addEventListener("click", closeDrawer); $("#drawerBackdrop").addEventListener("click", closeDrawer);
  document.addEventListener("keydown", event => { if (event.key === "Escape") closeDrawer(); });
  $("#globalSearch").addEventListener("input", event => { search = event.target.value.trim().toLowerCase(); renderAll(); });
  $("#globalSearch").addEventListener("keydown", event => { if (event.key === "Enter" && search) setView("assets"); });
  document.addEventListener("keydown", event => { if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") { event.preventDefault(); $("#globalSearch").focus(); } });
  $("#themeButton").addEventListener("click", () => { document.body.classList.toggle("light"); renderAll(); });
  window.addEventListener("resize", () => { if ($("#overview").classList.contains("active")) { drawRiskChart(); drawSeverityChart(); } });
  uniqueOptions("#assetOsFilter", data.assets.map(x=>x.assetOsPrimary));
  [...new Set(data.assets.flatMap(asset => asset.perimeterIds || []))].sort().forEach(value => {
    const label = value.startsWith("system-") ? "Périmètre système / global" : `Périmètre · ${value.slice(0,8)}…`;
    $("#globalPerimeter").insertAdjacentHTML("beforeend", `<option value="${esc(value)}">${esc(label)}</option>`);
  });
  uniqueOptions("#globalProvider", data.assets.flatMap(asset => asset.providerIds || []));
  refreshServerOptions();
  uniqueOptions("#findingServerFilter", data.assets.map(x=>x.hostname).map(hostname => hostname));
  [...$("#findingServerFilter").options].slice(1).forEach((option,index) => {
    const asset = data.assets.find(item => item.hostname === option.value);
    if (asset) option.value = asset.assetId;
  });
  uniqueOptions("#findingSeverityFilter", data.criticalFindings.map(x=>x.severity));
  uniqueOptions("#findingProviderFilter", data.criticalFindings.map(x=>x.provider));
  uniqueOptions("#serverSeverityFilter", data.criticalFindings.map(x=>x.severity));
  uniqueOptions("#cveSeverityFilter", data.cves.map(x=>x.severity));
  renderAll();
})();
