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
    "trivy_critical_max":   5,
    "trivy_high_max":       30,

    # SonarCloud SAST
    "sonar_vulnerabilities_max": 50,
    "sonar_hotspots_max":        80,

    # OWASP ZAP DAST
    "zap_high_max":         5,

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
    branch  = os.environ.get("GITHUB_REF_NAME",   "—")
    sha     = os.environ.get("GITHUB_SHA",         "local")[:8]
    actor   = os.environ.get("GITHUB_ACTOR",       "—")

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
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&family=Space+Grotesk:wght@300;400;500;600;700&family=IBM+Plex+Mono:wght@300;400;500;600&display=swap" rel="stylesheet">
  <style>
    :root {{
      --bg:#0a0f1e;--surface:#0f172a;--surface2:#1e293b;
      --border:rgba(255,255,255,0.07);--border2:rgba(56,189,248,0.22);
      --accent:#38bdf8;--accent2:#818cf8;--muted:#94a3b8;--text:#e2e8f0;
      --ok:#22c55e;--danger:#ef4444;--warn:#f97316;
      --font-h:'Space Grotesk',sans-serif;--font-m:'JetBrains Mono',monospace;
    }}
    [data-theme="light"] {{
      --bg:#f1f5f9;--surface:#ffffff;--surface2:#e2e8f0;
      --border:rgba(0,0,0,0.08);--border2:rgba(2,132,199,0.25);
      --accent:#0284c7;--accent2:#6366f1;--muted:#475569;--text:#1e293b;
      --ok:#16a34a;--danger:#dc2626;--warn:#ea580c;
    }}
    *,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
    body{{background:var(--bg);color:var(--text);font-family:var(--font-h);
          min-height:100vh;overflow-x:hidden;transition:background .3s,color .3s}}

    /* ── THEME TOGGLE ── */
    #tgl{{position:fixed;top:20px;right:20px;z-index:9999;display:flex;gap:8px}}
    .tb{{width:44px;height:36px;border:1px solid var(--border);
      background:var(--surface);color:var(--text);
      border-radius:22px;cursor:pointer;font-size:16px;
      display:flex;align-items:center;justify-content:center;
      transition:all .25s;backdrop-filter:blur(10px)}}
    .tb:hover{{transform:translateY(-2px);border-color:var(--accent)}}
    .tb.active{{border-color:var(--accent);box-shadow:0 0 0 2px var(--accent)}}

    /* ── HEADER (style generate_dashboard) ── */
    .dash-header {{
      background:linear-gradient(135deg,#0f172a 0%,#1e3a5f 60%,#0f172a 100%);
      border-bottom:1px solid var(--border);
      padding:28px 40px 22px;
      position:relative;overflow:hidden;
    }}
    [data-theme="light"] .dash-header {{
      background:linear-gradient(135deg,#e0f2fe 0%,#bae6fd 60%,#e0f2fe 100%);
    }}
    .dash-header::before {{
      content:'';position:absolute;inset:0;
      background:radial-gradient(ellipse at 70% 50%,rgba(56,189,248,.08) 0%,transparent 60%);
      pointer-events:none;
    }}
    .header-eyebrow {{
      font-family:'JetBrains Mono',monospace;
      font-size:.65rem;letter-spacing:.2em;
      color:var(--accent);text-transform:uppercase;
      margin-bottom:8px;
      display:flex;align-items:center;gap:6px;
    }}
    .live-dot {{
      display:inline-block;width:7px;height:7px;
      border-radius:50%;background:var(--ok);
      margin-right:6px;vertical-align:middle;
      animation:livePulse 2s ease-in-out infinite;
    }}
    @keyframes livePulse {{
      0%,100%{{box-shadow:0 0 0 0 rgba(34,197,94,0.5)}}
      50%{{box-shadow:0 0 0 6px rgba(34,197,94,0)}}
    }}
    .dash-header h1 {{
      font-family:'JetBrains Mono',monospace;
      font-size:1.6rem;font-weight:700;letter-spacing:.04em;
      color:#f8fafc;
    }}
    [data-theme="light"] .dash-header h1{{color:#0f172a}}
    .dash-header h1 span{{color:#7dd3fc}}
    .dash-header p{{color:var(--muted);font-size:.85rem;margin-top:4px}}
    .cursor-blink {{
      display:inline-block;width:2px;height:1em;
      background:var(--accent);margin-left:3px;
      vertical-align:middle;
      animation:cursorBlink .9s step-end infinite;
    }}
    @keyframes cursorBlink{{0%,100%{{opacity:1}}50%{{opacity:0}}}}
    .meta-row{{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}}
    .meta-pill {{
      background:rgba(255,255,255,.06);border:1px solid var(--border);
      border-radius:20px;padding:3px 12px;
      font-family:'JetBrains Mono',monospace;font-size:.72rem;color:var(--muted);
    }}
    [data-theme="light"] .meta-pill{{background:rgba(0,0,0,.04)}}
    .meta-pill a{{color:var(--accent);text-decoration:none}}

    /* ── GATE STATUS PILL ── */
    .gate-pill {{
      display:inline-flex;align-items:center;gap:6px;
      padding:3px 14px;border-radius:20px;
      font-family:'JetBrains Mono',monospace;
      font-size:.75rem;font-weight:700;letter-spacing:.08em;
      border:1px solid currentColor;margin-top:10px;
    }}
    .gate-pill.pass{{color:var(--ok);background:rgba(34,197,94,0.10)}}
    .gate-pill.fail{{
      color:var(--danger);background:rgba(239,68,68,0.12);
      animation:dangerPulse 2s ease-in-out infinite;
    }}
    @keyframes dangerPulse{{
      0%,100%{{box-shadow:0 0 8px rgba(239,68,68,0.2)}}
      50%{{box-shadow:0 0 18px rgba(239,68,68,0.45)}}
    }}

    /* ── BODY LAYOUT ── */
    .wrap{{max-width:860px;margin:0 auto;padding:32px 24px 60px}}
    .section-lbl{{
      font-family:'JetBrains Mono',monospace;
      font-size:.68rem;font-weight:700;letter-spacing:.14em;
      text-transform:uppercase;color:var(--muted);
      margin:32px 0 12px;
      display:flex;align-items:center;gap:10px;
    }}
    .section-lbl::after{{content:'';flex:1;height:1px;background:var(--border)}}

    /* Decision + Score ring */
    .decision{{
      background:var(--surface);border:1px solid var(--border);
      border-left:5px solid {gate_color};
      border-radius:14px;padding:20px 28px;margin-bottom:24px;
      display:flex;align-items:center;gap:28px;flex-wrap:wrap;
    }}
    .decision-label{{
      font-family:'JetBrains Mono',monospace;font-size:1.1rem;font-weight:700;
      color:{gate_color};letter-spacing:.02em;
    }}
    .decision-sub{{font-size:.72rem;color:var(--muted);margin-top:3px}}
    .score-ring{{position:relative;width:110px;height:110px;flex-shrink:0}}
    .score-ring svg{{transform:rotate(-90deg)}}
    .score-center{{
      position:absolute;inset:0;display:flex;flex-direction:column;
      align-items:center;justify-content:center;
    }}
    .score-num{{
      font-family:'JetBrains Mono',monospace;font-size:1.5rem;font-weight:700;
      color:{score_color};line-height:1;
    }}
    .score-sub{{font-size:.6rem;color:var(--muted);letter-spacing:.08em}}

    /* Checks table */
    .card{{
      background:var(--surface);border:1px solid var(--border);
      border-radius:12px;overflow:hidden;
      transition:border-color .3s;
    }}
    .card:hover{{border-color:var(--border2)}}
    table{{width:100%;border-collapse:collapse}}
    thead tr{{background:rgba(56,189,248,0.05)}}
    thead th{{
      padding:10px 14px;font-size:.67rem;letter-spacing:.12em;
      text-transform:uppercase;color:var(--muted);text-align:left;
      border-bottom:1px solid var(--border2);
      font-family:'JetBrains Mono',monospace;
    }}
    thead th:nth-child(2),thead th:nth-child(3){{text-align:center}}
    thead th:last-child{{text-align:right}}

    /* Thresholds */
    .thresh-grid{{display:grid;grid-template-columns:1fr 1fr;gap:0}}

    /* Footer */
    footer{{
      text-align:center;margin-top:36px;font-size:.67rem;color:var(--muted);
      border-top:1px solid var(--border);padding-top:20px;
      font-family:'JetBrains Mono',monospace;
    }}
    footer a{{color:var(--accent);text-decoration:none}}

    /* Animations */
    .fade-in{{opacity:0;transform:translateY(16px);animation:fadeUp .5s ease forwards}}
    @keyframes fadeUp{{to{{opacity:1;transform:translateY(0)}}}}
    .d1{{animation-delay:.05s}}.d2{{animation-delay:.12s}}
    .d3{{animation-delay:.18s}}.d4{{animation-delay:.24s}}
  </style>
</head>
<body>

<!-- ── THEME TOGGLE ── -->
<div id="tgl">
  <button id="dm" class="tb active" title="Dark Mode">🌙</button>
  <button id="lm" class="tb"        title="Light Mode">☀️</button>
</div>

<!-- ── HEADER (style generate_dashboard) ── -->
<div class="dash-header fade-in d1">
  <div class="header-eyebrow">
    <span class="live-dot"></span>DevSecOps Pipeline &nbsp;·&nbsp; Quality Gate
  </div>
  <h1>🚦 Quality <span>Gate</span> Report<span class="cursor-blink"></span></h1>
  <p>Pipeline CI/CD — Projet WebGoat</p>
  <div class="meta-row">
    <span class="meta-pill">🔀 {branch}</span>
    <span class="meta-pill">📦 {sha}</span>
    <span class="meta-pill">🔢 Run #{run_num}</span>
    <span class="meta-pill">👤 {actor}</span>
    <span class="meta-pill">🕐 {timestamp}</span>
    <span class="meta-pill"><a href="{run_url}" target="_blank">🔗 GitHub Actions</a></span>
  </div>
  <div>
    <span class="gate-pill {'pass' if all_passed else 'fail'}">
      {gate_icon} {gate_label}
    </span>
  </div>
</div>

<!-- ── BODY ── -->
<div class="wrap">

  <!-- Decision + Score -->
  <div class="section-lbl d2">Décision finale</div>
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
    <span class="live-dot"></span>
    Quality Gate · DevSecOps WebGoat ·
    <a href="{run_url}" target="_blank">Run #{run_num}</a>
  </footer>

</div>

<!-- ── THEME SCRIPT ── -->
<script>
(function(){{
  const r=document.documentElement,dm=document.getElementById('dm'),lm=document.getElementById('lm');
  function st(t){{
    r.setAttribute('data-theme',t);
    localStorage.setItem('devsecops-theme',t);
    [dm,lm].forEach(b=>b.classList.remove('active'));
    document.getElementById(t==='dark'?'dm':'lm').classList.add('active');
  }}
  st(localStorage.getItem('devsecops-theme')
    ||(window.matchMedia('(prefers-color-scheme:dark)').matches?'dark':'light'));
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
