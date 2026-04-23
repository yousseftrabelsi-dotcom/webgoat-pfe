import json
import os
import re
import sys
from datetime import datetime, timezone

import plotly.graph_objects as go


# ─────────────────────────────────────────────────────────────────────────────
# 1. COLLECTE DES DONNÉES
# ─────────────────────────────────────────────────────────────────────────────

def parse_trivy(path: str) -> dict:
    """Parse le rapport JSON de Trivy. Retourne des compteurs réels ou zéros."""
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    if not os.path.isfile(path):
        print(f"[WARN] Trivy : fichier introuvable ({path})", file=sys.stderr)
        return counts
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        for result in data.get("Results", []):
            for vuln in result.get("Vulnerabilities", []):
                sev = vuln.get("Severity", "").capitalize()
                if sev in counts:
                    counts[sev] += 1
    except json.JSONDecodeError as e:
        print(f"[ERROR] Trivy JSON invalide : {e}", file=sys.stderr)
    except Exception as e:
        print(f"[ERROR] Lecture Trivy : {e}", file=sys.stderr)
    return counts


def parse_falco(path: str) -> dict:
    """Parse les logs JSON de Falco ligne par ligne."""
    counts = {"Notice": 0, "Warning": 0, "Error": 0, "Critical": 0}
    if not os.path.isfile(path):
        print(f"[WARN] Falco : fichier introuvable ({path})", file=sys.stderr)
        return counts
    try:
        with open(path, encoding="utf-8") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    log = json.loads(line)
                    prio = log.get("priority", "").capitalize()
                    if prio in counts:
                        counts[prio] += 1
                except json.JSONDecodeError:
                    # Ligne non-JSON (logs de démarrage Falco) — on ignore
                    pass
    except Exception as e:
        print(f"[ERROR] Lecture Falco : {e}", file=sys.stderr)
    return counts


def parse_gitleaks(candidates: list[str]) -> int:
    """Cherche le premier fichier SARIF/JSON valide parmi les candidats."""
    for path in candidates:
        if not os.path.isfile(path):
            continue
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                count = len(data)
            elif isinstance(data, dict) and "runs" in data:
                count = len(data["runs"][0].get("results", []))
            else:
                count = 0
            print(f"[INFO] Gitleaks : {count} secret(s) trouvé(s) dans {path}")
            return count
        except json.JSONDecodeError as e:
            print(f"[WARN] Gitleaks JSON invalide ({path}) : {e}", file=sys.stderr)
        except Exception as e:
            print(f"[ERROR] Lecture Gitleaks ({path}) : {e}", file=sys.stderr)
    print("[WARN] Gitleaks : aucun fichier de rapport trouvé.", file=sys.stderr)
    return 0


def parse_zap(path: str) -> dict:
    """
    Parse le rapport JSON de ZAP s'il existe.
    ZAP peut aussi produire un HTML — on extrait alors les alertes par regex.
    """
    counts = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    if not os.path.isfile(path):
        print(f"[WARN] ZAP : fichier introuvable ({path})", file=sys.stderr)
        return counts
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        for site in data.get("site", []):
            for alert in site.get("alerts", []):
                risk = alert.get("riskdesc", "").split(" ")[0]
                if risk in counts:
                    counts[risk] += 1
    except json.JSONDecodeError:
        # Rapport HTML — extraction par regex des compteurs de risques
        try:
            with open(path, encoding="utf-8") as f:
                html = f.read()
            for risk in counts:
                m = re.search(
                    rf'<td[^>]*>\s*{risk}\s*</td>\s*<td[^>]*>\s*(\d+)\s*</td>',
                    html, re.IGNORECASE
                )
                if m:
                    counts[risk] = int(m.group(1))
        except Exception as e:
            print(f"[ERROR] Lecture ZAP HTML : {e}", file=sys.stderr)
    except Exception as e:
        print(f"[ERROR] Lecture ZAP : {e}", file=sys.stderr)
    return counts


def parse_ai_summary(path: str) -> str:
    """Lit le résumé IA et le nettoie (Markdown → texte plat)."""
    fallback = (
        "Analyse IA non disponible pour ce run. "
        "Vérifiez la configuration de la clé GEMINI_API_KEY."
    )
    if not os.path.isfile(path):
        return fallback
    try:
        with open(path, encoding="utf-8") as f:
            raw = f.read().strip()
        if not raw:
            return fallback
        clean = re.sub(r"[*#>`-]", "", raw)
        clean = re.sub(r"\s+", " ", clean).strip()
        sentences = [s.strip() for s in clean.split(".") if len(s.strip()) > 10]
        return ". ".join(sentences[:4]) + "." if sentences else fallback
    except Exception as e:
        print(f"[ERROR] Lecture résumé IA : {e}", file=sys.stderr)
        return fallback


# ─────────────────────────────────────────────────────────────────────────────
# 2. CALCUL DU SCORE DE RISQUE GLOBAL
# ─────────────────────────────────────────────────────────────────────────────

def compute_risk_score(trivy: dict, falco: dict, gitleaks: int, zap: dict) -> dict:
    """
    Calcule un score de risque normalisé sur 100 (100 = risque maximal).
    Pondération :
      - Secrets détectés     : bloquant (score 100 immédiat si > 0)
      - CVE Critical Trivy   : poids 8
      - CVE High Trivy       : poids 3
      - Alertes Falco Error+ : poids 10
      - Alertes ZAP High     : poids 5
    """
    if gitleaks > 0:
        return {"score": 100, "status": "BLOQUANT", "color": "#c0392b",
                "reason": f"{gitleaks} secret(s) en clair détecté(s) — déploiement bloqué."}

    raw = (
        trivy.get("Critical", 0) * 8 +
        trivy.get("High", 0) * 3 +
        (falco.get("Error", 0) + falco.get("Critical", 0)) * 10 +
        zap.get("High", 0) * 5
    )
    score = min(100, raw)

    if score >= 70:
        return {"score": score, "status": "CRITIQUE", "color": "#c0392b",
                "reason": "Vulnérabilités critiques nécessitant une action immédiate."}
    if score >= 40:
        return {"score": score, "status": "ÉLEVÉ", "color": "#e67e22",
                "reason": "Risques significatifs à corriger avant déploiement."}
    if score >= 15:
        return {"score": score, "status": "MODÉRÉ", "color": "#f39c12",
                "reason": "Améliorations recommandées, déploiement possible avec vigilance."}
    return {"score": score, "status": "FAIBLE", "color": "#27ae60",
            "reason": "Aucune vulnérabilité critique détectée."}


# ─────────────────────────────────────────────────────────────────────────────
# 3. CRÉATION DES FIGURES PLOTLY
# ─────────────────────────────────────────────────────────────────────────────

TRANSPARENT_LAYOUT = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    margin=dict(t=40, b=20, l=20, r=20),
    height=280,
    font=dict(family="Segoe UI, Tahoma, Geneva, Verdana, sans-serif"),
)


def fig_sca(trivy: dict) -> go.Figure:
    total = sum(trivy.values())
    labels = list(trivy.keys())
    values = list(trivy.values())
    colors = ["#d32f2f", "#f57c00", "#fbc02d", "#388e3c"]

    if total == 0:
        fig = go.Figure()
        fig.add_annotation(text="Aucune vulnérabilité détectée ✓",
                           xref="paper", yref="paper", x=0.5, y=0.5,
                           showarrow=False, font=dict(size=14, color="#388e3c"))
    else:
        fig = go.Figure(data=[go.Pie(
            labels=labels, values=values, hole=0.4,
            marker=dict(colors=colors),
            textinfo="label+value",
        )])
    fig.update_layout(**TRANSPARENT_LAYOUT,
                      title_text=f"SCA — {total} CVE détectées", title_x=0.5)
    return fig


def fig_sast_placeholder() -> go.Figure:
    """
    SAST : données issues de SonarCloud via API ou fixées manuellement.
    TODO : remplacer par un appel à l'API SonarCloud
    (GET /api/issues/search?componentKeys=<key>&resolved=false)
    """
    fig = go.Figure(data=[go.Bar(
        x=["Bugs", "Vulnérabilités", "Hotspots"],
        y=[375, 40, 66],
        marker_color=["#1976D2", "#D32F2F", "#FFA000"],
        text=[375, 40, 66],
        textposition="auto",
    )])
    fig.add_annotation(
        text="⚠ Données statiques — intégrer l'API SonarCloud",
        xref="paper", yref="paper", x=0.5, y=-0.15,
        showarrow=False, font=dict(size=10, color="#888"),
    )
    fig.update_layout(**TRANSPARENT_LAYOUT,
                      title_text="SAST — Analyse SonarCloud", title_x=0.5)
    return fig


def fig_dast(zap: dict) -> go.Figure:
    labels = list(zap.keys())
    values = list(zap.values())
    total = sum(values)

    if total == 0:
        fig = go.Figure()
        fig.add_annotation(text="Aucune alerte ZAP détectée ✓",
                           xref="paper", yref="paper", x=0.5, y=0.5,
                           showarrow=False, font=dict(size=14, color="#388e3c"))
    else:
        fig = go.Figure(data=[go.Bar(
            x=labels, y=values,
            marker_color=["#D32F2F", "#F57C00", "#FBC02D", "#1976D2"],
            text=values, textposition="auto",
        )])
    fig.update_layout(**TRANSPARENT_LAYOUT,
                      title_text=f"DAST — {total} alertes ZAP", title_x=0.5)
    return fig


def fig_falco_chart(falco: dict) -> go.Figure:
    total = sum(falco.values())
    fig = go.Figure(data=[go.Bar(
        x=list(falco.keys()),
        y=list(falco.values()),
        marker_color=["#4CAF50", "#FF9800", "#E91E63", "#B71C1C"],
        text=list(falco.values()),
        textposition="auto",
    )])
    fig.update_layout(**TRANSPARENT_LAYOUT,
                      title_text=f"Runtime — {total} détections Falco", title_x=0.5)
    return fig


def fig_secrets_gauge(count: int) -> go.Figure:
    max_val = max(5, count + 2)
    bar_color = "#D32F2F" if count > 0 else "#2E7D32"
    fig = go.Figure(go.Indicator(
        mode="number+gauge",
        value=count,
        title={"text": "Secrets détectés"},
        gauge={
            "axis": {"range": [0, max_val]},
            "bar": {"color": bar_color},
            "steps": [{"range": [1, max_val], "color": "rgba(255,0,0,0.1)"}],
            "threshold": {
                "line": {"color": "red", "width": 3},
                "thickness": 0.75,
                "value": 1,
            },
        },
    ))
    fig.update_layout(**TRANSPARENT_LAYOUT)
    return fig


# ─────────────────────────────────────────────────────────────────────────────
# 4. GÉNÉRATION DU HTML
# ─────────────────────────────────────────────────────────────────────────────

def generate_dashboard():
    # — Lecture des données réelles —
    trivy   = parse_trivy("trivy-results.json")
    falco   = parse_falco("falco-results.json")
    zap     = parse_zap("report_html.html")
    gitleaks = parse_gitleaks([
        "gitleaks-results.sarif/results.sarif",
        "gitleaks-results.sarif/gitleaks.sarif",
        "results.sarif",
        "gitleaks-report.json",
    ])
    ai_summary = parse_ai_summary("ai-security-summary.txt")
    risk       = compute_risk_score(trivy, falco, gitleaks, zap)

    # — Métadonnées du run GitHub Actions —
    meta = {
        "sha":       os.environ.get("GITHUB_SHA", "N/A")[:8],
        "run":       os.environ.get("GITHUB_RUN_NUMBER", "N/A"),
        "branch":    os.environ.get("GITHUB_REF_NAME", "N/A"),
        "actor":     os.environ.get("GITHUB_ACTOR", "N/A"),
        "run_url":   os.environ.get("GITHUB_RUN_URL", "#"),
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    }

    # — Figures —
    f_sca   = fig_sca(trivy).to_html(full_html=False, include_plotlyjs=False)
    f_sast  = fig_sast_placeholder().to_html(full_html=False, include_plotlyjs=False)
    f_dast  = fig_dast(zap).to_html(full_html=False, include_plotlyjs=False)
    f_falco = fig_falco_chart(falco).to_html(full_html=False, include_plotlyjs=False)
    f_sec   = fig_secrets_gauge(gitleaks).to_html(full_html=False, include_plotlyjs=False)

    # — Résumé des totaux pour les cartes KPI —
    total_cve     = sum(trivy.values())
    total_falco   = sum(falco.values())
    total_zap     = sum(zap.values())

    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>DevSecOps Dashboard — Run #{meta['run']}</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
  <style>
    body {{ background:#f1f5f9; color:#1e293b; font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif; }}
    .header-section {{
      background:linear-gradient(135deg,#0f172a 0%,#1d4ed8 100%);
      color:white; padding:30px 0 20px; border-radius:0 0 20px 20px; margin-bottom:28px;
    }}
    .meta-badge {{
      display:inline-block; background:rgba(255,255,255,.15);
      border-radius:6px; padding:3px 10px; font-size:.78rem; margin:3px 4px;
    }}
    .card {{ border:none; box-shadow:0 2px 8px rgba(0,0,0,.07); border-radius:14px; margin-bottom:20px; }}
    .kpi-card {{ background:white; border-radius:10px; padding:14px 18px; text-align:center;
                 box-shadow:0 1px 4px rgba(0,0,0,.06); }}
    .kpi-value {{ font-size:2rem; font-weight:700; line-height:1.1; }}
    .kpi-label {{ font-size:.78rem; color:#64748b; margin-top:2px; }}
    .risk-banner {{
      border-radius:12px; padding:16px 24px;
      border-left:6px solid {risk['color']};
      background:white; margin-bottom:20px;
      box-shadow:0 2px 8px rgba(0,0,0,.07);
    }}
    .risk-score {{ font-size:3rem; font-weight:700; color:{risk['color']}; line-height:1; }}
    .ai-box {{
      background:#ecfeff; border-left:5px solid #06b6d4;
      padding:16px 20px; border-radius:8px;
      font-size:1rem; line-height:1.7; color:#083344;
    }}
    .note-box {{
      background:#f8fafc; border-left:3px solid #94a3b8;
      padding:8px 12px; font-size:.8rem; border-radius:4px; margin-top:8px; color:#475569;
    }}
    .section-title {{
      font-size:.7rem; font-weight:600; letter-spacing:.08em;
      text-transform:uppercase; color:#94a3b8; margin-bottom:12px;
    }}
    @media(max-width:768px) {{ .kpi-value {{ font-size:1.5rem; }} }}
  </style>
</head>
<body>

<div class="header-section text-center">
  <h1 class="fw-bold mb-2">🛡️ DevSecOps Executive Dashboard</h1>
  <p class="mb-2" style="opacity:.8">Pipeline CI/CD — Projet WebGoat</p>
  <div>
    <span class="meta-badge">🔀 Branche : {meta['branch']}</span>
    <span class="meta-badge">📦 Commit : {meta['sha']}</span>
    <span class="meta-badge">🔢 Run #{meta['run']}</span>
    <span class="meta-badge">👤 {meta['actor']}</span>
    <span class="meta-badge">🕐 {meta['timestamp']}</span>
    <a href="{meta['run_url']}" class="meta-badge" style="color:white;text-decoration:none" target="_blank">
      🔗 Voir le run GitHub Actions
    </a>
  </div>
</div>

<div class="container-fluid px-4">

  <!-- SCORE DE RISQUE GLOBAL -->
  <p class="section-title">Score de risque global</p>
  <div class="risk-banner d-flex align-items-center gap-4 flex-wrap">
    <div class="risk-score">{risk['score']}<span style="font-size:1.2rem;color:#94a3b8">/100</span></div>
    <div>
      <span class="badge fs-6 mb-1" style="background:{risk['color']}">{risk['status']}</span>
      <p class="mb-0 text-muted small">{risk['reason']}</p>
    </div>
    <div class="ms-auto">
      <div style="width:120px;height:12px;background:#e2e8f0;border-radius:6px;overflow:hidden">
        <div style="width:{risk['score']}%;height:100%;background:{risk['color']};transition:width .5s"></div>
      </div>
    </div>
  </div>

  <!-- KPI CARDS -->
  <p class="section-title">Résumé des scans</p>
  <div class="row g-3 mb-4">
    <div class="col-6 col-md-3">
      <div class="kpi-card">
        <div class="kpi-value" style="color:#d32f2f">{gitleaks}</div>
        <div class="kpi-label">🔑 Secrets détectés</div>
      </div>
    </div>
    <div class="col-6 col-md-3">
      <div class="kpi-card">
        <div class="kpi-value" style="color:#f57c00">{total_cve}</div>
        <div class="kpi-label">📦 CVE (dépendances)</div>
      </div>
    </div>
    <div class="col-6 col-md-3">
      <div class="kpi-card">
        <div class="kpi-value" style="color:#673ab7">{total_zap}</div>
        <div class="kpi-label">🌐 Alertes DAST</div>
      </div>
    </div>
    <div class="col-6 col-md-3">
      <div class="kpi-card">
        <div class="kpi-value" style="color:#e91e63">{total_falco}</div>
        <div class="kpi-label">⚡ Événements Runtime</div>
      </div>
    </div>
  </div>

  <!-- SYNTHÈSE IA -->
  <div class="card p-4 mb-2">
    <h5 class="fw-bold text-info border-bottom pb-2">🤖 Synthèse de l'Intelligence Artificielle</h5>
    <div class="ai-box">{ai_summary}</div>
  </div>

  <!-- GRAPHIQUES LIGNE 1 -->
  <p class="section-title mt-4">Analyse détaillée</p>
  <div class="row">
    <div class="col-md-4">
      <div class="card p-3">
        <h6 class="text-center text-secondary fw-bold border-bottom pb-2">SCA — Dépendances (Trivy)</h6>
        {f_sca}
        <div class="note-box">CVE détectées dans les librairies tierces. Données réelles du scan.</div>
      </div>
    </div>
    <div class="col-md-4">
      <div class="card p-3">
        <h6 class="text-center text-secondary fw-bold border-bottom pb-2">SAST — Code Source (SonarCloud)</h6>
        {f_sast}
        <div class="note-box">Dette technique. Intégrer l'API SonarCloud pour des données dynamiques.</div>
      </div>
    </div>
    <div class="col-md-4">
      <div class="card p-3">
        <h6 class="text-center text-secondary fw-bold border-bottom pb-2">DAST — Attaques Web (ZAP)</h6>
        {f_dast}
        <div class="note-box">Alertes issues du scan OWASP ZAP sur le conteneur WebGoat.</div>
      </div>
    </div>
  </div>

  <!-- GRAPHIQUES LIGNE 2 -->
  <div class="row">
    <div class="col-md-6">
      <div class="card p-3">
        <h6 class="text-center text-secondary fw-bold border-bottom pb-2">Runtime — Intrusions (Falco)</h6>
        {f_falco}
        <div class="note-box">Détections Falco. Comportements suspects capturés en temps réel.</div>
      </div>
    </div>
    <div class="col-md-6">
      <div class="card p-3">
        <h6 class="text-center text-secondary fw-bold border-bottom pb-2">Secrets — Scan Git (Gitleaks)</h6>
        {f_sec}
        <div class="note-box">Secrets en clair détectés dans les commits. Zéro tolérance recommandée.</div>
      </div>
    </div>
  </div>

  <footer class="text-center my-4 text-muted small">
    Généré automatiquement par GitHub Actions — Run #{ meta['run'] } —
    <a href="{meta['run_url']}" target="_blank">Voir le pipeline complet</a>
  </footer>
</div>
</body>
</html>"""

    output_path = "global_security_report.html"
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[OK] Dashboard généré : {output_path}")


if __name__ == "__main__":
    generate_dashboard()
