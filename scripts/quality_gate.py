"""
scripts/quality_gate.py
──────────────────────────────────────────────────────────────────────────────
Quality Gate DevSecOps — Bloque le pipeline si les seuils de risque sont
dépassés. Lit les rapports du pipeline et produit un rapport de décision.

Codes de sortie :
  0 → PASS   (déploiement autorisé)
  1 → FAIL   (déploiement bloqué)
──────────────────────────────────────────────────────────────────────────────
"""

import json
import os
import sys
from datetime import datetime, timezone

# ─────────────────────────────────────────────────────────────────────────────
# SEUILS — modifier selon la politique de sécurité du projet
# ─────────────────────────────────────────────────────────────────────────────

THRESHOLDS = {
    # Secrets : zéro tolérance absolue
    "secrets_max":          0,

    # Trivy SCA
    "trivy_critical_max":   0,    # 0 CVE critique tolérée
    "trivy_high_max":       5,    # max 5 CVE élevées

    # SonarCloud SAST
    "sonar_vulnerabilities_max": 10,
    "sonar_hotspots_max":        20,

    # OWASP ZAP DAST
    "zap_high_max":         0,    # 0 alerte haute tolérée

    # Falco Runtime
    "falco_critical_max":   0,
    "falco_error_max":      5,

    # Score global
    "risk_score_max":       69,   # CRITIQUE = score >= 70
}

OUTPUT_FILE     = "quality-gate-report.html"
OUTPUT_FILE_TXT = "quality-gate-report.txt"


# ─────────────────────────────────────────────────────────────────────────────
# PARSEURS (versions légères, sans dépendances externes)
# ─────────────────────────────────────────────────────────────────────────────

def _load_json(path: str) -> dict | list | None:
    if not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def get_gitleaks_count() -> int:
    for path in ("results.sarif", "gitleaks-report.json"):
        data = _load_json(path)
        if data is None:
            continue
        if isinstance(data, list):
            return len(data)
        if isinstance(data, dict) and "runs" in data:
            return len(data["runs"][0].get("results", []))
    return 0


def get_trivy_counts() -> dict:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    data = _load_json("trivy-results.json")
    if not data:
        return counts
    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            sev = vuln.get("Severity", "").capitalize()
            if sev in counts:
                counts[sev] += 1
    return counts


def get_sonar_counts() -> dict:
    defaults = {"vulnerabilities": 0, "security_hotspots": 0, "bugs": 0}
    data = _load_json("sonar-results.json")
    if not data:
        return defaults
    for m in data.get("component", {}).get("measures", []):
        metric = m.get("metric")
        if metric in defaults:
            defaults[metric] = int(m.get("value", 0))
    return defaults


def get_zap_counts() -> dict:
    counts = {"High": 0, "Medium": 0, "Low": 0}
    data = _load_json("report_json.json")
    if not data:
        return counts
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            risk = alert.get("riskdesc", "").split(" ")[0]
            if risk in counts:
                counts[risk] += 1
    return counts


def get_falco_counts() -> dict:
    counts = {"Notice": 0, "Warning": 0, "Error": 0, "Critical": 0}
    if not os.path.isfile("falco-results.json"):
        return counts
    try:
        with open("falco-results.json", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    log = json.loads(line)
                    prio = log.get("priority", "").capitalize()
                    if prio in counts:
                        counts[prio] += 1
                except json.JSONDecodeError:
                    pass
    except Exception:
        pass
    return counts


def compute_score(trivy, falco, secrets, zap) -> int:
    if secrets > 0:
        return 100
    raw = (
        trivy.get("Critical", 0) * 8
        + trivy.get("High", 0)   * 3
        + (falco.get("Error", 0) + falco.get("Critical", 0)) * 10
        + zap.get("High", 0)     * 5
    )
    return min(100, raw)


# ─────────────────────────────────────────────────────────────────────────────
# ÉVALUATION DES SEUILS
# ─────────────────────────────────────────────────────────────────────────────

def evaluate(label: str, value: int, max_allowed: int) -> dict:
    passed = value <= max_allowed
    return {
        "label":       label,
        "value":       value,
        "max_allowed": max_allowed,
        "passed":      passed,
        "symbol":      "✅ PASS" if passed else "❌ FAIL",
    }


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print("\n" + "═" * 60)
    print("  Quality Gate — DevSecOps WebGoat Pipeline")
    print("═" * 60)

    # Collecte des métriques
    secrets  = get_gitleaks_count()
    trivy    = get_trivy_counts()
    sonar    = get_sonar_counts()
    zap      = get_zap_counts()
    falco    = get_falco_counts()
    score    = compute_score(trivy, falco, secrets, zap)

    T = THRESHOLDS

    checks = [
        evaluate("🔑 Secrets détectés",           secrets,                    T["secrets_max"]),
        evaluate("💣 CVE Critiques (Trivy)",       trivy["Critical"],          T["trivy_critical_max"]),
        evaluate("🔶 CVE Élevées (Trivy)",         trivy["High"],              T["trivy_high_max"]),
        evaluate("🐛 Vulnérabilités SAST (Sonar)", sonar["vulnerabilities"],   T["sonar_vulnerabilities_max"]),
        evaluate("🔥 Hotspots SAST (Sonar)",       sonar["security_hotspots"], T["sonar_hotspots_max"]),
        evaluate("🌐 Alertes Hautes (ZAP)",        zap["High"],                T["zap_high_max"]),
        evaluate("⚡ Erreurs Runtime (Falco)",     falco["Error"],             T["falco_error_max"]),
        evaluate("🚨 Critiques Runtime (Falco)",   falco["Critical"],          T["falco_critical_max"]),
        evaluate("🎯 Score de Risque Global",       score,                     T["risk_score_max"]),
    ]

    all_passed = all(c["passed"] for c in checks)
    decision   = "✅  DÉPLOIEMENT AUTORISÉ" if all_passed else "🚫  DÉPLOIEMENT BLOQUÉ"
    timestamp  = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # ── Affichage console ─────────────────────────────────────────
    print(f"\n{'Vérification':<40} {'Valeur':>8}  {'Max':>6}  Résultat")
    print("─" * 72)
    for c in checks:
        print(f"  {c['label']:<38} {c['value']:>8}  {c['max_allowed']:>6}  {c['symbol']}")
    print("─" * 72)
    print(f"\n  Score global : {score}/100")
    print(f"\n  ╔══════════════════════════════════╗")
    print(f"  ║  {decision:<32}║")
    print(f"  ╚══════════════════════════════════╝\n")

    # ── Rapport TXT (gardé pour notify_slack.py) ────────────────
    txt_lines = [
        "═" * 60,
        "  Quality Gate Report — DevSecOps WebGoat",
        f"  Généré le : {timestamp}",
        f"  Run       : #{os.environ.get('GITHUB_RUN_NUMBER', '—')}",
        "═" * 60,
        f"  Score global : {score}/100",
        f"  DÉCISION FINALE : {decision}",
    ]
    for c in checks:
        txt_lines.append(f"  {c['label']:<38} {c['value']:>8}  {c['max_allowed']:>6}  {c['symbol']}")
    with open(OUTPUT_FILE_TXT, "w", encoding="utf-8") as fh:
        fh.write("\n".join(txt_lines))

    # ── Dashboard HTML ────────────────────────────────────────────
    run_url = os.environ.get("GITHUB_RUN_URL", "#")
    run_num = os.environ.get("GITHUB_RUN_NUMBER", "—")

    # Couleur globale selon décision
    gate_color  = "#00ffa3" if all_passed else "#ff3d5a"
    gate_icon   = "✅" if all_passed else "🚫"
    gate_label  = "DÉPLOIEMENT AUTORISÉ" if all_passed else "DÉPLOIEMENT BLOQUÉ"

    # Score ring — stroke-dasharray trick
    circumference = 2 * 3.14159 * 52  # r=52
    dash_fill = (score / 100) * circumference
    score_color = "#00ffa3" if score < 40 else ("#ff8c00" if score < 70 else "#ff3d5a")

    def check_row(c):
        bg    = "rgba(0,255,163,0.04)"  if c["passed"] else "rgba(255,61,90,0.06)"
        dot   = "#00ffa3"               if c["passed"] else "#ff3d5a"
        sym   = "✅ PASS"               if c["passed"] else "❌ FAIL"
        sym_c = "#00ffa3"               if c["passed"] else "#ff3d5a"
        bar_w = min(100, int(c["value"] / max(c["max_allowed"] * 2, 1) * 100)) if c["max_allowed"] > 0 else (100 if c["value"] > 0 else 0)
        bar_c = dot
        return f"""
        <tr style="background:{bg};border-bottom:1px solid rgba(0,200,255,0.07)">
          <td style="padding:11px 14px;font-size:.78rem;color:#cfe8ff">
            <span style="display:inline-block;width:7px;height:7px;border-radius:50%;background:{dot};margin-right:8px;box-shadow:0 0 6px {dot}"></span>
            {c['label']}
          </td>
          <td style="padding:11px 14px;text-align:center;font-weight:700;color:{sym_c};font-size:.85rem;letter-spacing:.05em">{c['value']}</td>
          <td style="padding:11px 14px;text-align:center;color:#5a8aaa;font-size:.78rem">{c['max_allowed']}</td>
          <td style="padding:11px 14px;min-width:120px">
            <div style="background:rgba(255,255,255,0.05);border-radius:3px;height:4px;overflow:hidden">
              <div style="width:{bar_w}%;height:100%;background:{bar_c};border-radius:3px;transition:width .8s ease"></div>
            </div>
          </td>
          <td style="padding:11px 14px;text-align:right;font-size:.75rem;color:{sym_c};font-weight:600;letter-spacing:.08em">{sym}</td>
        </tr>"""

    rows_html = "".join(check_row(c) for c in checks)

    # Seuils table
    def thresh_row(key, val):
        return f"""<tr style="border-bottom:1px solid rgba(0,200,255,0.05)">
          <td style="padding:7px 14px;color:#5a8aaa;font-size:.72rem;font-family:'IBM Plex Mono',monospace">{key}</td>
          <td style="padding:7px 14px;text-align:right;color:#00c8ff;font-size:.72rem;font-family:'IBM Plex Mono',monospace;font-weight:600">{val}</td>
        </tr>"""
    thresh_html = "".join(thresh_row(k, v) for k, v in THRESHOLDS.items())

    html = f"""<!DOCTYPE html>
<html lang="fr" data-theme="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Quality Gate — Run #{run_num}</title>
  <link href="https://fonts.googleapis.com/css2?family=Syne:wght@400;700;800&family=IBM+Plex+Mono:wght@300;400;500;600&display=swap" rel="stylesheet">
  <style>
    :root {{
      --bg:#020b18;--surface:#071428;--surface2:#0c1f3a;
      --border:rgba(0,200,255,0.10);--border2:rgba(0,200,255,0.22);
      --accent:#00c8ff;--muted:#5a8aaa;--text:#cfe8ff;
      --font-h:'Syne',sans-serif;--font-m:'IBM Plex Mono',monospace;
    }}
    [data-theme="light"]{{
      --bg:#f0f6ff;--surface:#ffffff;--surface2:#ddeeff;
      --border:rgba(0,100,200,0.10);--border2:rgba(0,100,200,0.25);
      --accent:#0077cc;--muted:#4a6a8a;--text:#0f2a45;
    }}
    *,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
    body{{background:var(--bg);color:var(--text);font-family:var(--font-m);
          min-height:100vh;overflow-x:hidden;transition:background .3s,color .3s}}
    body::before{{content:'';position:fixed;inset:0;z-index:0;
      background-image:linear-gradient(rgba(0,200,255,0.025) 1px,transparent 1px),
        linear-gradient(90deg,rgba(0,200,255,0.025) 1px,transparent 1px);
      background-size:40px 40px;animation:gp 8s ease-in-out infinite;pointer-events:none}}
    [data-theme="light"] body::before{{background-image:
      linear-gradient(rgba(0,100,200,0.04) 1px,transparent 1px),
      linear-gradient(90deg,rgba(0,100,200,0.04) 1px,transparent 1px)}}
    @keyframes gp{{0%,100%{{opacity:1}}50%{{opacity:.4}}}}
    .wrap{{position:relative;z-index:2;max-width:860px;margin:0 auto;padding:32px 24px 60px}}

    /* Header */
    .qg-header{{background:linear-gradient(160deg,#020d1e,#061830,#020d1e);
      border:1px solid var(--border2);border-radius:14px;padding:28px 32px;
      margin-bottom:28px;position:relative;overflow:hidden}}
    [data-theme="light"] .qg-header{{background:linear-gradient(160deg,#ddeeff,#c8e0f8,#ddeeff)}}
    .qg-header::before{{content:'';position:absolute;width:400px;height:400px;
      background:radial-gradient(circle,rgba(0,200,255,0.06) 0%,transparent 70%);
      top:-150px;right:-80px;pointer-events:none}}
    .eyebrow{{font-size:.62rem;letter-spacing:.22em;color:var(--accent);
      text-transform:uppercase;margin-bottom:10px;display:flex;align-items:center;gap:8px}}
    .eyebrow::before{{content:'';display:inline-block;width:18px;height:1px;background:var(--accent)}}
    .qg-title{{font-family:var(--font-h);font-size:1.6rem;font-weight:800;color:var(--text);
      letter-spacing:-.01em;line-height:1.1}}
    .qg-title span{{color:var(--accent)}}
    .meta-pills{{display:flex;flex-wrap:wrap;gap:6px;margin-top:14px}}
    .pill{{background:rgba(0,200,255,0.06);border:1px solid var(--border2);
      border-radius:5px;padding:3px 10px;font-size:.67rem;color:var(--muted)}}
    .pill a{{color:var(--accent);text-decoration:none}}

    /* Theme toggle */
    #tgl{{position:fixed;top:16px;right:16px;z-index:9999;display:flex;gap:5px}}
    .tb{{width:34px;height:30px;border:1px solid var(--border2);background:var(--surface);
      color:var(--accent);border-radius:7px;cursor:pointer;font-size:13px;
      display:flex;align-items:center;justify-content:center;transition:all .2s}}
    .tb:hover,.tb.active{{box-shadow:0 0 10px rgba(0,200,255,0.3);border-color:var(--accent)}}

    /* Decision banner */
    .decision{{border-radius:12px;padding:20px 26px;margin-bottom:24px;
      border-left:4px solid {gate_color};background:var(--surface);
      display:flex;align-items:center;gap:20px;flex-wrap:wrap;
      box-shadow:0 0 24px rgba(0,200,255,0.06)}}
    .decision-icon{{font-size:2rem}}
    .decision-label{{font-family:var(--font-h);font-size:1.15rem;font-weight:800;
      color:{gate_color};letter-spacing:.02em}}
    .decision-sub{{font-size:.72rem;color:var(--muted);margin-top:3px}}

    /* Score ring */
    .score-ring{{position:relative;width:110px;height:110px;flex-shrink:0}}
    .score-ring svg{{transform:rotate(-90deg)}}
    .score-center{{position:absolute;inset:0;display:flex;flex-direction:column;
      align-items:center;justify-content:center}}
    .score-num{{font-family:var(--font-h);font-size:1.5rem;font-weight:800;
      color:{score_color};line-height:1}}
    .score-sub{{font-size:.6rem;color:var(--muted);letter-spacing:.08em}}

    /* Checks table */
    .section-lbl{{font-size:.62rem;letter-spacing:.18em;text-transform:uppercase;
      color:var(--accent);margin:24px 0 12px;display:flex;align-items:center;gap:10px}}
    .section-lbl::before{{content:'//';color:#7c3aed}}
    .section-lbl::after{{content:'';flex:1;height:1px;background:linear-gradient(90deg,var(--border2),transparent)}}
    .card{{background:var(--surface);border:1px solid var(--border);border-radius:12px;
      overflow:hidden;transition:border-color .3s,box-shadow .3s}}
    .card:hover{{border-color:var(--border2);box-shadow:0 0 20px rgba(0,200,255,0.08)}}
    table{{width:100%;border-collapse:collapse}}
    thead tr{{background:rgba(0,200,255,0.05)}}
    thead th{{padding:10px 14px;font-size:.67rem;letter-spacing:.12em;
      text-transform:uppercase;color:var(--muted);text-align:left;
      border-bottom:1px solid var(--border2)}}
    thead th:nth-child(2),thead th:nth-child(3){{text-align:center}}
    thead th:last-child{{text-align:right}}

    /* Thresholds */
    .thresh-grid{{display:grid;grid-template-columns:1fr 1fr;gap:0}}

    /* Footer */
    footer{{text-align:center;margin-top:36px;font-size:.67rem;color:var(--muted);
      border-top:1px solid var(--border);padding-top:20px;position:relative}}
    footer::before{{content:'';position:absolute;top:0;left:50%;transform:translateX(-50%);
      width:60px;height:1px;background:linear-gradient(90deg,transparent,var(--accent),transparent)}}
    footer a{{color:var(--accent);text-decoration:none}}
    .live{{display:inline-block;width:6px;height:6px;border-radius:50%;
      background:#00ffa3;margin-right:6px;
      animation:pulse 2s ease-in-out infinite}}
    @keyframes pulse{{0%,100%{{box-shadow:0 0 0 0 rgba(0,255,163,.5)}}50%{{box-shadow:0 0 0 5px rgba(0,255,163,0)}}}}

    /* Animations */
    .fade-in{{opacity:0;transform:translateY(16px);
      animation:fadeUp .5s ease forwards}}
    @keyframes fadeUp{{to{{opacity:1;transform:translateY(0)}}}}
    .d1{{animation-delay:.05s}}.d2{{animation-delay:.12s}}
    .d3{{animation-delay:.18s}}.d4{{animation-delay:.24s}}
  </style>
</head>
<body>

<div id="tgl">
  <button id="dm" class="tb active" title="Dark">🌙</button>
  <button id="lm" class="tb"        title="Light">☀️</button>
</div>

<div class="wrap">

  <!-- Header -->
  <div class="qg-header fade-in d1">
    <div class="eyebrow"><span class="live"></span>DevSecOps Pipeline · Quality Gate</div>
    <div class="qg-title">🚦 Quality <span>Gate</span> Report</div>
    <div class="meta-pills">
      <span class="pill">🔢 Run #{run_num}</span>
      <span class="pill">🕐 {timestamp}</span>
      <span class="pill"><a href="{run_url}" target="_blank">🔗 GitHub Actions</a></span>
    </div>
  </div>

  <!-- Decision + Score -->
  <div class="decision fade-in d2">
    <div class="score-ring">
      <svg width="110" height="110" viewBox="0 0 110 110">
        <circle cx="55" cy="55" r="52" fill="none" stroke="rgba(255,255,255,0.05)" stroke-width="8"/>
        <circle cx="55" cy="55" r="52" fill="none" stroke="{score_color}" stroke-width="8"
          stroke-dasharray="{dash_fill:.1f} {circumference:.1f}"
          stroke-linecap="round" style="transition:stroke-dasharray 1s ease"/>
      </svg>
      <div class="score-center">
        <div class="score-num">{score}</div>
        <div class="score-sub">/100</div>
      </div>
    </div>
    <div>
      <div class="decision-label">{gate_icon} {gate_label}</div>
      <div class="decision-sub">Score de risque global · {timestamp}</div>
    </div>
  </div>

  <!-- Checks table -->
  <div class="section-lbl d3">Vérifications de sécurité</div>
  <div class="card fade-in d3">
    <table>
      <thead>
        <tr>
          <th>Vérification</th>
          <th>Valeur</th>
          <th>Max</th>
          <th style="min-width:100px">Progression</th>
          <th>Résultat</th>
        </tr>
      </thead>
      <tbody>{rows_html}</tbody>
    </table>
  </div>

  <!-- Seuils -->
  <div class="section-lbl">Seuils appliqués</div>
  <div class="card fade-in d4">
    <table class="thresh-grid">
      <tbody>{thresh_html}</tbody>
    </table>
  </div>

  <footer>
    <span class="live"></span>
    Quality Gate · DevSecOps WebGoat ·
    <a href="{run_url}" target="_blank">Run #{run_num}</a>
  </footer>

</div>

<script>
(function(){{
  const r=document.documentElement,dm=document.getElementById('dm'),lm=document.getElementById('lm');
  function st(t){{r.setAttribute('data-theme',t);localStorage.setItem('qg-t',t);
    [dm,lm].forEach(b=>b.classList.remove('active'));
    document.getElementById(t==='dark'?'dm':'lm').classList.add('active');}}
  st(localStorage.getItem('qg-t')||(window.matchMedia('(prefers-color-scheme:dark)').matches?'dark':'light'));
  dm.addEventListener('click',()=>st('dark'));
  lm.addEventListener('click',()=>st('light'));
}})();
</script>
</body>
</html>"""

    with open(OUTPUT_FILE, "w", encoding="utf-8") as fh:
        fh.write(html)
    print(f"[OK] Dashboard Quality Gate → {OUTPUT_FILE}")
    print(f"[OK] Rapport texte         → {OUTPUT_FILE_TXT}")

    # ── Sortie pipeline ───────────────────────────────────────────
    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    main()
