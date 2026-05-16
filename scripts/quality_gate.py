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

    gate_icon  = "✅" if all_passed else "🚫"
    gate_label = "DÉPLOIEMENT AUTORISÉ" if all_passed else "DÉPLOIEMENT BLOQUÉ"
    pill_class = "ok" if all_passed else ("high" if score < 70 else "blocking")

    circumference = 2 * 3.14159 * 52
    dash_fill   = (score / 100) * circumference
    score_color = "#22c55e" if score < 40 else ("#f97316" if score < 70 else "#ef4444")
    risk_reason = (
        f"{secrets} secret(s) en clair — déploiement bloqué immédiatement." if secrets > 0
        else "Vulnérabilités critiques — action immédiate requise." if score >= 70
        else "Risques significatifs à corriger avant tout déploiement." if score >= 40
        else "Aucune vulnérabilité critique détectée."
    )

    def check_row(c):
        dot_c = "#22c55e" if c["passed"] else "#ef4444"
        sym_c = "#22c55e" if c["passed"] else "#ef4444"
        sym   = "✅ PASS"  if c["passed"] else "❌ FAIL"
        row_bg = "rgba(34,197,94,0.03)" if c["passed"] else "rgba(239,68,68,0.04)"
        if c["max_allowed"] > 0:
            bar_w = min(100, round(c["value"] / c["max_allowed"] * 100))
        else:
            bar_w = 100 if c["value"] > 0 else 0
        return f"""<tr style="background:{row_bg}">
          <td style="padding:12px 16px;font-size:.82rem;color:var(--text);display:flex;align-items:center;gap:10px">
            <span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:{dot_c};box-shadow:0 0 5px {dot_c};flex-shrink:0"></span>
            {c['label']}
          </td>
          <td style="padding:12px 16px;text-align:center;font-family:'JetBrains Mono',monospace;font-size:.9rem;font-weight:700;color:{sym_c}">{c['value']}</td>
          <td style="padding:12px 16px;text-align:center;font-family:'JetBrains Mono',monospace;font-size:.8rem;color:var(--muted)">{c['max_allowed']}</td>
          <td style="padding:12px 16px;min-width:120px">
            <div style="background:rgba(255,255,255,0.07);border-radius:3px;height:5px;overflow:hidden">
              <div style="width:{bar_w}%;height:100%;background:{dot_c};border-radius:3px;transition:width .8s ease"></div>
            </div>
          </td>
          <td style="padding:12px 16px;text-align:right;font-family:'JetBrains Mono',monospace;font-size:.75rem;font-weight:700;color:{sym_c};letter-spacing:.08em">{sym}</td>
        </tr>"""

    rows_html = "".join(check_row(c) for c in checks)

    def thresh_row(key, val):
        return f"""<tr style="border-bottom:1px solid var(--border)">
          <td style="padding:9px 16px;font-family:'JetBrains Mono',monospace;font-size:.75rem;color:var(--muted)">{key}</td>
          <td style="padding:9px 16px;text-align:right;font-family:'JetBrains Mono',monospace;font-size:.75rem;font-weight:600;color:var(--accent)">{val}</td>
        </tr>"""
    thresh_html = "".join(thresh_row(k, v) for k, v in THRESHOLDS.items())

        html = f"""<!DOCTYPE html>
<html lang="fr" data-theme="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Quality Gate — Run #{run_num}</title>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&family=Space+Grotesk:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    :root {{
      --bg:       #0a0f1e;
      --surface:  #0f172a;
      --surface2: #1e293b;
      --border:   rgba(255,255,255,0.07);
      --accent:   #38bdf8;
      --accent2:  #818cf8;
      --danger:   #ef4444;
      --warn:     #f97316;
      --ok:       #22c55e;
      --text:     #e2e8f0;
      --muted:    #94a3b8;
    }}
    [data-theme="light"] {{
      --bg:       #f1f5f9;
      --surface:  #ffffff;
      --surface2: #e2e8f0;
      --border:   rgba(0,0,0,0.08);
      --accent:   #0284c7;
      --accent2:  #6366f1;
      --danger:   #dc2626;
      --warn:     #ea580c;
      --ok:       #16a34a;
      --text:     #1e293b;
      --muted:    #475569;
    }}
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background: var(--bg); color: var(--text);
      font-family: 'Space Grotesk', sans-serif;
      font-size: 14px; line-height: 1.6;
      min-height: 100vh; transition: background .3s, color .3s;
    }}

    /* ── THEME TOGGLE ── */
    #theme-toggle {{
      position: fixed; top: 20px; right: 20px; z-index: 9999;
      display: flex; gap: 8px;
    }}
    .theme-btn {{
      width: 44px; height: 36px; border: 1px solid var(--border);
      background: var(--surface); color: var(--text);
      border-radius: 22px; cursor: pointer; font-size: 16px;
      display: flex; align-items: center; justify-content: center;
      transition: all .25s;
    }}
    .theme-btn:hover  {{ transform: translateY(-2px); border-color: var(--accent); }}
    .theme-btn.active {{ border-color: var(--accent); box-shadow: 0 0 0 2px var(--accent); }}

    /* ── HEADER ── */
    .dash-header {{
      background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 60%, #0f172a 100%);
      border-bottom: 1px solid var(--border);
      padding: 28px 40px 22px;
      position: relative; overflow: hidden;
    }}
    [data-theme="light"] .dash-header {{
      background: linear-gradient(135deg, #e0f2fe 0%, #bae6fd 60%, #e0f2fe 100%);
    }}
    .dash-header::before {{
      content: ''; position: absolute; inset: 0;
      background: radial-gradient(ellipse at 70% 50%, rgba(56,189,248,.08) 0%, transparent 60%);
      pointer-events: none;
    }}
    .header-eyebrow {{
      font-family: 'JetBrains Mono', monospace;
      font-size: .65rem; letter-spacing: .2em; color: var(--accent);
      text-transform: uppercase; margin-bottom: 8px;
      display: flex; align-items: center; gap: 6px;
    }}
    .dash-header h1 {{
      font-family: 'JetBrains Mono', monospace;
      font-size: 1.5rem; font-weight: 700; letter-spacing: .04em; color: #f8fafc;
    }}
    [data-theme="light"] .dash-header h1 {{ color: #0f172a; }}
    .dash-header h1 span {{ color: #7dd3fc; }}
    .dash-header p {{ color: var(--muted); font-size: .85rem; margin-top: 4px; }}
    .meta-row {{ display: flex; flex-wrap: wrap; gap: 8px; margin-top: 12px; align-items: center; }}
    .meta-pill {{
      background: rgba(255,255,255,.06); border: 1px solid var(--border);
      border-radius: 20px; padding: 3px 12px;
      font-family: 'JetBrains Mono', monospace; font-size: .72rem; color: var(--muted);
      transition: all .2s;
    }}
    [data-theme="light"] .meta-pill {{ background: rgba(0,0,0,.04); }}
    .meta-pill a {{ color: var(--accent); text-decoration: none; }}
    .meta-pill-dashboard {{
      background: rgba(56,189,248,0.10);
      border: 1px solid rgba(56,189,248,0.4);
      border-radius: 20px; padding: 4px 14px;
      font-family: 'JetBrains Mono', monospace; font-size: .72rem;
      color: var(--accent); font-weight: 600;
      text-decoration: none; cursor: pointer;
      transition: all .2s; display: inline-flex; align-items: center; gap: 5px;
    }}
    .meta-pill-dashboard:hover {{
      background: rgba(56,189,248,0.2);
      box-shadow: 0 0 12px rgba(56,189,248,0.25);
      transform: translateY(-1px);
      color: var(--accent);
    }}

    /* ── SECTION LABEL ── */
    .section-label {{
      font-family: 'JetBrains Mono', monospace;
      font-size: .68rem; font-weight: 700; letter-spacing: .14em;
      text-transform: uppercase; color: var(--muted);
      margin: 32px 0 12px;
      display: flex; align-items: center; gap: 10px;
    }}
    .section-label::after {{
      content: ''; flex: 1; height: 1px; background: var(--border);
    }}

    /* ── CARDS ── */
    .card-dark {{
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 14px; overflow: hidden;
      transition: border-color .25s;
    }}
    .card-dark:hover {{ border-color: rgba(56,189,248,.25); }}
    .card-title {{
      font-family: 'JetBrains Mono', monospace;
      font-size: .75rem; font-weight: 600; letter-spacing: .1em;
      text-transform: uppercase; color: var(--muted);
      padding: 14px 18px 12px; border-bottom: 1px solid var(--border);
      display: flex; align-items: center; gap: 8px;
    }}

    /* ── DECISION BANNER ── */
    .decision-banner {{
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 14px; padding: 20px 28px;
      display: flex; align-items: center; gap: 24px; flex-wrap: wrap;
    }}

    /* ── SCORE RING ── */
    .score-ring {{ position: relative; width: 120px; height: 120px; flex-shrink: 0; }}
    .score-ring svg {{ transform: rotate(-90deg); }}
    .score-center {{
      position: absolute; inset: 0;
      display: flex; flex-direction: column;
      align-items: center; justify-content: center;
    }}
    .score-num {{
      font-family: 'JetBrains Mono', monospace;
      font-size: 1.8rem; font-weight: 700; line-height: 1;
    }}
    .score-sub {{ font-size: .65rem; color: var(--muted); margin-top: 2px; }}

    /* ── STATUS PILL ── */
    .risk-status-pill {{
      display: inline-flex; align-items: center; gap: 5px;
      padding: 5px 16px; border-radius: 6px;
      font-family: 'JetBrains Mono', monospace;
      font-size: .75rem; font-weight: 700;
      letter-spacing: .1em; text-transform: uppercase;
      border: 1px solid currentColor; margin-bottom: 6px;
    }}
    .risk-status-pill.blocking {{
      color: var(--danger); background: rgba(239,68,68,0.10);
      border-color: var(--danger);
      animation: dangerPulse 2s ease-in-out infinite;
    }}
    @keyframes dangerPulse {{
      0%, 100% {{ box-shadow: 0 0 8px rgba(239,68,68,0.2); }}
      50%       {{ box-shadow: 0 0 20px rgba(239,68,68,0.5); }}
    }}
    .risk-status-pill.ok   {{ color:var(--ok);   background:rgba(34,197,94,0.08);  border-color:var(--ok);   }}
    .risk-status-pill.high {{ color:var(--warn);  background:rgba(249,115,22,0.08); border-color:var(--warn); }}
    .decision-reason {{ font-size: .82rem; color: var(--muted); margin: 0; }}

    /* ── RISK BAR ── */
    .risk-bar-outer {{
      flex: 1; min-width: 120px; height: 7px;
      background: rgba(255,255,255,.07); border-radius: 4px; overflow: hidden;
    }}
    [data-theme="light"] .risk-bar-outer {{ background: rgba(0,0,0,.07); }}
    .risk-bar-inner {{
      height: 100%; border-radius: 4px;
      transition: width .8s cubic-bezier(.4,0,.2,1);
    }}

    /* ── CHECKS TABLE ── */
    .checks-table {{ width: 100%; border-collapse: collapse; }}
    .checks-table thead tr {{ background: rgba(56,189,248,0.05); }}
    .checks-table thead th {{
      padding: 11px 16px;
      font-family: 'JetBrains Mono', monospace;
      font-size: .67rem; letter-spacing: .12em;
      text-transform: uppercase; color: var(--muted);
      border-bottom: 1px solid var(--border); font-weight: 600;
    }}
    .checks-table thead th:nth-child(2),
    .checks-table thead th:nth-child(3) {{ text-align: center; }}
    .checks-table thead th:last-child {{ text-align: right; padding-right: 16px; }}
    .checks-table tbody tr {{ border-bottom: 1px solid var(--border); transition: background .15s; }}
    .checks-table tbody tr:hover {{ background: rgba(255,255,255,0.02); }}
    .checks-table tbody tr:last-child {{ border-bottom: none; }}

    /* ── THRESHOLDS ── */
    .thresh-table {{ width: 100%; border-collapse: collapse; }}
    .thresh-table tr {{ border-bottom: 1px solid var(--border); }}
    .thresh-table tr:last-child {{ border-bottom: none; }}

    /* ── LIVE DOT ── */
    .live-dot {{
      display: inline-block; width: 7px; height: 7px;
      border-radius: 50%; background: var(--ok);
      margin-right: 2px; vertical-align: middle;
      animation: livePulse 2s ease-in-out infinite;
    }}
    @keyframes livePulse {{
      0%, 100% {{ box-shadow: 0 0 0 0 rgba(34,197,94,0.5); }}
      50%       {{ box-shadow: 0 0 0 6px rgba(34,197,94,0); }}
    }}
    .cursor-blink {{
      display: inline-block; width: 2px; height: 1em;
      background: var(--accent); margin-left: 3px; vertical-align: middle;
      animation: cursorBlink .9s step-end infinite;
    }}
    @keyframes cursorBlink {{ 0%, 100% {{ opacity: 1; }} 50% {{ opacity: 0; }} }}

    /* ── NOTE ── */
    .note {{
      background: rgba(255,255,255,.03);
      border-left: 2px solid rgba(148,163,184,.3);
      padding: 7px 12px; font-size: .75rem; color: var(--muted);
      border-radius: 0 6px 6px 0; margin-top: 10px;
    }}

    /* ── FOOTER ── */
    footer {{
      text-align: center; padding: 28px 0 20px;
      font-family: 'JetBrains Mono', monospace; font-size: .72rem;
      color: var(--muted); border-top: 1px solid var(--border); margin-top: 40px;
    }}
    footer a {{ color: var(--accent); text-decoration: none; }}
  </style>
</head>
<body>

<div id="theme-toggle">
  <button id="dark-mode"  class="theme-btn active" title="Dark Mode">🌙</button>
  <button id="light-mode" class="theme-btn"        title="Light Mode">☀️</button>
</div>

<div class="dash-header">
  <div class="header-eyebrow">
    <span class="live-dot"></span>DevSecOps Pipeline &nbsp;·&nbsp; Quality Gate
  </div>
  <h1>🚦 Quality <span>Gate</span> Report<span class="cursor-blink"></span></h1>
  <p>Pipeline CI/CD — Projet WebGoat</p>
  <div class="meta-row">
    <span class="meta-pill">🔢 Run #{run_num}</span>
    <span class="meta-pill">🕐 {timestamp}</span>
    <span class="meta-pill"><a href="{run_url}" target="_blank">🔗 GitHub Actions</a></span>
    <a href="global_security_report.html" class="meta-pill-dashboard" target="_blank">
      📊 Dashboard Final →
    </a>
  </div>
</div>

<div style="padding:28px 40px">

  <!-- ── DÉCISION + SCORE ── -->
  <div class="section-label">Décision de déploiement</div>
  <div class="decision-banner mb-4">
    <div class="score-ring">
      <svg width="120" height="120" viewBox="0 0 120 120">
        <circle cx="60" cy="60" r="52" fill="none"
          stroke="rgba(255,255,255,0.06)" stroke-width="9"/>
        <circle cx="60" cy="60" r="52" fill="none"
          stroke="{score_color}" stroke-width="9"
          stroke-dasharray="{dash_fill:.1f} {circumference:.1f}"
          stroke-linecap="round"
          style="transition:stroke-dasharray 1s ease"/>
      </svg>
      <div class="score-center">
        <div class="score-num" style="color:{score_color}">{score}</div>
        <div class="score-sub">/100</div>
      </div>
    </div>
    <div style="flex:1;min-width:180px">
      <div class="risk-status-pill {pill_class}">{gate_icon} {gate_label}</div>
      <p class="decision-reason">{risk_reason}</p>
    </div>
    <div class="risk-bar-outer">
      <div class="risk-bar-inner" style="width:{score}%;background:{score_color}"></div>
    </div>
  </div>

  <!-- ── CHECKS TABLE ── -->
  <div class="section-label">Vérifications de sécurité</div>
  <div class="card-dark mb-4">
    <table class="checks-table">
      <thead>
        <tr>
          <th style="text-align:left">Vérification</th>
          <th>Valeur</th>
          <th>Max</th>
          <th style="min-width:120px">Progression</th>
          <th style="text-align:right">Résultat</th>
        </tr>
      </thead>
      <tbody>{rows_html}</tbody>
    </table>
  </div>

  <!-- ── SEUILS ── -->
  <div class="section-label">Seuils appliqués</div>
  <div class="card-dark mb-4">
    <div class="card-title">⚙️ Configuration — scripts/quality_gate.py</div>
    <table class="thresh-table">
      <tbody>{thresh_html}</tbody>
    </table>
  </div>

  <footer>
    Généré automatiquement · GitHub Actions · Run #{run_num} ·
    <a href="{run_url}" target="_blank">Voir le pipeline</a>
  </footer>

</div>

<script>
(function () {{
  const root=document.documentElement,
        dm=document.getElementById('dark-mode'),
        lm=document.getElementById('light-mode');
  function setTheme(t) {{
    root.setAttribute('data-theme', t);
    localStorage.setItem('qg-theme', t);
    [dm, lm].forEach(b => b.classList.remove('active'));
    document.getElementById(t + '-mode').classList.add('active');
  }}
  const saved = localStorage.getItem('qg-theme')
    || (window.matchMedia('(prefers-color-scheme:dark)').matches ? 'dark' : 'light');
  setTheme(saved);
  dm.addEventListener('click', () => setTheme('dark'));
  lm.addEventListener('click', () => setTheme('light'));
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
