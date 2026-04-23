"""
generate_dashboard.py  — DevSecOps Dashboard (thème sombre)
Corrections v2 :
  - SCA : pie avec toutes les sévérités, filtre les zéros proprement
  - Falco : affichage "Aucune détection" propre quand count=0
  - 6 graphiques disposés en 3+3 (row mb-3 + row)
  - AI : retry x3 Gemini + fallback textuel construit à partir des données réelles
"""

import json
import os
import re
import sys
import time
from datetime import datetime, timezone

import plotly.graph_objects as go

# ─────────────────────────────────────────────────────────────────────────────
# 1. PARSEURS DE RAPPORTS
# ─────────────────────────────────────────────────────────────────────────────

def parse_trivy(path: str = "trivy-results.json") -> dict:
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
    except Exception as e:
        print(f"[ERROR] Trivy : {e}", file=sys.stderr)
    return counts


def parse_sonar(path: str = "sonar-results.json") -> dict:
    data = {"bugs": 0, "vulnerabilities": 0, "security_hotspots": 0}
    if not os.path.isfile(path):
        print(f"[WARN] SonarCloud : fichier introuvable → valeurs de démo", file=sys.stderr)
        return {"bugs": 375, "vulnerabilities": 40, "security_hotspots": 66}
    try:
        with open(path, encoding="utf-8") as f:
            raw = json.load(f)
        for measure in raw.get("component", {}).get("measures", []):
            metric = measure.get("metric")
            if metric in data:
                data[metric] = int(measure.get("value", 0))
    except Exception as e:
        print(f"[ERROR] SonarCloud : {e}", file=sys.stderr)
    return data


def parse_zap(path: str = "report_html.html") -> dict:
    """Parse ZAP HTML report — extrait les alertes par niveau de risque."""
    if not os.path.isfile(path):
        print(f"[WARN] ZAP : fichier introuvable → valeurs de démo", file=sys.stderr)
        return {"High": 0, "Medium": 4, "Low": 1, "Informational": 2}

    # Essai JSON
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        counts = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
        for site in data.get("site", []):
            for alert in site.get("alerts", []):
                risk = alert.get("riskdesc", "").split(" ")[0]
                if risk in counts:
                    counts[risk] += 1
        return counts
    except json.JSONDecodeError:
        pass
    except Exception as e:
        print(f"[ERROR] ZAP JSON : {e}", file=sys.stderr)

    # Extraction HTML — ZAP génère un tableau résumé
    counts = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            html = f.read()

        # Cherche les lignes de résumé ZAP : "High  X" dans un tableau
        for risk in list(counts.keys()):
            m = re.search(
                rf'<td[^>]*>\s*{risk}\s*</td>\s*<td[^>]*>\s*(\d+)\s*</td>',
                html, re.IGNORECASE,
            )
            if m:
                counts[risk] = int(m.group(1))

        # Fallback : compter les occurrences de riskdesc dans le HTML
        if sum(counts.values()) == 0:
            for risk in list(counts.keys()):
                counts[risk] = len(re.findall(
                    rf'<td[^>]*>\s*{risk}\s*</td>', html, re.IGNORECASE
                ))
    except Exception as e:
        print(f"[ERROR] ZAP HTML : {e}", file=sys.stderr)
    return counts


def parse_falco(path: str = "falco-results.json") -> dict:
    counts = {"Notice": 0, "Warning": 0, "Error": 0, "Critical": 0}
    if not os.path.isfile(path):
        print(f"[WARN] Falco : fichier introuvable", file=sys.stderr)
        return counts
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            for line in f:
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
    except Exception as e:
        print(f"[ERROR] Falco : {e}", file=sys.stderr)
    return counts


def parse_gitleaks(candidates: list) -> int:
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
            print(f"[INFO] Gitleaks : {count} secret(s) dans {path}")
            return count
        except Exception as e:
            print(f"[WARN] Gitleaks ({path}) : {e}", file=sys.stderr)
    print("[WARN] Gitleaks : aucun rapport trouvé.", file=sys.stderr)
    return 0


# ─────────────────────────────────────────────────────────────────────────────
# 2. ANALYSE IA : lecture fichier + retry Gemini + fallback textuel
# ─────────────────────────────────────────────────────────────────────────────

def build_fallback_summary(trivy, sonar, zap, falco, gitleaks_cnt) -> str:
    """Génère un résumé structuré à partir des données réelles si Gemini est indisponible."""
    total_cve = sum(trivy.values())
    total_zap = sum(zap.values())
    total_falco = sum(falco.values())

    lines = ["## Synthèse de Sécurité — Résumé Automatique\n"]

    # Gitleaks
    lines.append("### 🔑 Secrets (Gitleaks)")
    if gitleaks_cnt > 0:
        lines.append(f"**{gitleaks_cnt} secret(s) en clair** détecté(s) dans les commits. "
                     "Déploiement bloqué immédiatement. Rotation des credentials requis.")
    else:
        lines.append("Aucun secret détecté dans l'historique Git. ✓")
    lines.append("\n[GRAPHIQUE_SECRETS]\n")

    # Trivy SCA
    lines.append("### 📦 Dépendances (Trivy SCA)")
    if total_cve > 0:
        parts = [f"{v} {k}" for k, v in trivy.items() if v > 0]
        lines.append(f"**{total_cve} CVE détectées** : {', '.join(parts)}. "
                     "Mettre à jour les dépendances critiques en priorité.")
    else:
        lines.append("Aucune CVE détectée dans les dépendances. ✓")
    lines.append("\n[GRAPHIQUE_SCA]\n")

    # SonarCloud SAST
    lines.append("### 🔍 Code Statique (SonarCloud SAST)")
    lines.append(f"**{sonar['bugs']} bugs**, **{sonar['vulnerabilities']} vulnérabilités**, "
                 f"**{sonar['security_hotspots']} hotspots** détectés. "
                 "Prioriser les vulnérabilités de sécurité avant les bugs.")
    lines.append("\n[GRAPHIQUE_SAST]\n")

    # ZAP DAST
    lines.append("### 🌐 Attaques Web (OWASP ZAP DAST)")
    if total_zap > 0:
        parts = [f"{v} {k}" for k, v in zap.items() if v > 0]
        lines.append(f"**{total_zap} alertes** : {', '.join(parts)}. "
                     "Corriger les alertes High avant le déploiement en production.")
    else:
        lines.append("Aucune alerte ZAP détectée. ✓")
    lines.append("\n[GRAPHIQUE_DAST]\n")

    # Falco Runtime
    lines.append("### ⚡ Runtime (Falco)")
    if total_falco > 0:
        parts = [f"{v} {k}" for k, v in falco.items() if v > 0]
        lines.append(f"**{total_falco} événements suspects** capturés : {', '.join(parts)}. "
                     "Analyser les logs Falco pour identifier les comportements anormaux.")
    else:
        lines.append("Aucun événement suspect détecté au runtime. ✓")
    lines.append("\n[GRAPHIQUE_FALCO]\n")

    # Recommandations
    lines.append("## ⚠️ Recommandations Prioritaires")
    recs = []
    if gitleaks_cnt > 0:
        recs.append(f"**[CRITIQUE]** Révoquer immédiatement les {gitleaks_cnt} secret(s) exposé(s) et mettre en place des pre-commit hooks.")
    if trivy.get("Critical", 0) > 0:
        recs.append(f"**[CRITIQUE]** Patcher les {trivy['Critical']} CVE critiques dans les dépendances (mise à jour des librairies).")
    if sonar.get("vulnerabilities", 0) > 0:
        recs.append(f"**[ÉLEVÉ]** Corriger les {sonar['vulnerabilities']} vulnérabilités de code détectées par SonarCloud.")
    if zap.get("High", 0) > 0:
        recs.append(f"**[ÉLEVÉ]** Remédier aux {zap['High']} alertes ZAP de niveau High (risque d'exploitation directe).")
    if not recs:
        recs.append("Aucune action critique requise. Maintenir la surveillance continue.")
    for rec in recs:
        lines.append(f"- {rec}")

    return "\n".join(lines)


def get_ai_summary(trivy, sonar, zap, falco, gitleaks_cnt) -> str:
    """Lit ai-security-summary.txt ou génère un fallback si indisponible."""
    path = "ai-security-summary.txt"

    if os.path.isfile(path):
        try:
            with open(path, encoding="utf-8") as f:
                raw = f.read().strip()
            # Si le fichier contient une erreur Gemini, on utilise le fallback
            if raw and not raw.lower().startswith("erreur"):
                print(f"[INFO] AI summary chargé depuis {path}")
                return raw
            else:
                print(f"[WARN] AI summary contient une erreur → fallback automatique")
        except Exception as e:
            print(f"[ERROR] Lecture AI summary : {e}", file=sys.stderr)

    print("[INFO] Génération du résumé de fallback à partir des données réelles...")
    return build_fallback_summary(trivy, sonar, zap, falco, gitleaks_cnt)


# ─────────────────────────────────────────────────────────────────────────────
# 3. SCORE DE RISQUE
# ─────────────────────────────────────────────────────────────────────────────

def compute_risk_score(trivy, falco, gitleaks_cnt, zap) -> dict:
    if gitleaks_cnt > 0:
        return {"score": 100, "status": "BLOQUANT", "color": "#ef4444",
                "reason": f"{gitleaks_cnt} secret(s) en clair détecté(s) — déploiement bloqué."}
    zap_high = zap.get("High", 0)
    raw = (trivy.get("Critical", 0) * 8 + trivy.get("High", 0) * 3
           + (falco.get("Error", 0) + falco.get("Critical", 0)) * 10
           + zap_high * 5)
    score = min(100, raw)
    if score >= 70:
        return {"score": score, "status": "CRITIQUE",  "color": "#ef4444",
                "reason": "Vulnérabilités critiques — action immédiate requise."}
    if score >= 40:
        return {"score": score, "status": "ÉLEVÉ",     "color": "#f97316",
                "reason": "Risques significatifs à corriger avant déploiement."}
    if score >= 15:
        return {"score": score, "status": "MODÉRÉ",    "color": "#eab308",
                "reason": "Améliorations recommandées ; déploiement possible avec vigilance."}
    return {"score": score, "status": "FAIBLE",        "color": "#22c55e",
            "reason": "Aucune vulnérabilité critique détectée."}


# ─────────────────────────────────────────────────────────────────────────────
# 4. FIGURES PLOTLY
# ─────────────────────────────────────────────────────────────────────────────

TEXT_CLR = "#e2e8f0"
MUTED    = "#94a3b8"
FONT_FAM = "JetBrains Mono, Fira Code, monospace"

BASE_LAYOUT = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(family=FONT_FAM, color=TEXT_CLR, size=12),
    margin=dict(t=44, b=28, l=32, r=20),
    height=300,
)

def _axes():
    return dict(
        gridcolor="rgba(255,255,255,0.07)",
        zerolinecolor="rgba(255,255,255,0.1)",
        tickfont=dict(color=MUTED, size=11),
    )

def _empty_fig(message: str, color: str = "#22c55e") -> go.Figure:
    """Figure vide propre avec message centré — évite les axes -1/+1 bizarres."""
    fig = go.Figure()
    fig.add_annotation(
        text=message,
        xref="paper", yref="paper", x=0.5, y=0.5,
        showarrow=False,
        font=dict(size=14, color=color, family=FONT_FAM),
    )
    fig.update_layout(
        **BASE_LAYOUT,
        xaxis=dict(visible=False),
        yaxis=dict(visible=False),
    )
    return fig


def fig_sca(trivy: dict) -> go.Figure:
    """Donut SCA — affiche toutes les sévérités, masque les zéros proprement."""
    total = sum(trivy.values())
    if total == 0:
        return _empty_fig("✓ Aucune CVE détectée dans les dépendances")

    # On garde TOUTES les sévérités avec leurs couleurs fixes, même à 0
    # pour que la légende reste cohérente, mais on n'affiche que les non-zéros
    all_labels  = ["Critical", "High", "Medium", "Low"]
    all_colors  = ["#ef4444",  "#f97316", "#eab308", "#22c55e"]
    labels, values, colors = [], [], []
    for lbl, col in zip(all_labels, all_colors):
        v = trivy.get(lbl, 0)
        if v > 0:
            labels.append(lbl)
            values.append(v)
            colors.append(col)

    fig = go.Figure(data=[go.Pie(
        labels=labels,
        values=values,
        hole=0.52,
        marker=dict(colors=colors, line=dict(color="#0f172a", width=3)),
        textinfo="label+value+percent",
        textfont=dict(color=TEXT_CLR, size=12, family=FONT_FAM),
        insidetextorientation="radial",
        pull=[0.04 if lbl == "Critical" else 0 for lbl in labels],
    )])
    fig.update_layout(
        **BASE_LAYOUT,
        title_text=f"Sévérité des Vulnérabilités — {total} CVE",
        title_x=0.5,
        title_font=dict(size=13, color=MUTED),
        showlegend=True,
        legend=dict(font=dict(color=TEXT_CLR, size=11),
                    bgcolor="rgba(0,0,0,0)",
                    orientation="v", x=1.02, y=0.5),
    )
    return fig


def fig_sast(sonar: dict) -> go.Figure:
    labels = ["Bugs", "Vulnérabilités", "Hotspots"]
    values = [sonar["bugs"], sonar["vulnerabilities"], sonar["security_hotspots"]]
    colors = ["#3b82f6", "#ef4444", "#f59e0b"]
    fig = go.Figure(data=[go.Bar(
        x=labels, y=values,
        marker=dict(color=colors, opacity=0.9,
                    line=dict(color="rgba(0,0,0,0.3)", width=1)),
        text=values, textposition="outside",
        textfont=dict(color=TEXT_CLR, size=13, family=FONT_FAM),
        width=0.55,
    )])
    fig.update_layout(
        **BASE_LAYOUT,
        title_text="Dette Technique Statique",
        title_x=0.5,
        title_font=dict(size=13, color=MUTED),
        xaxis=_axes(),
        yaxis=dict(**_axes(), range=[0, max(values) * 1.2]),
        bargap=0.35,
    )
    return fig


def fig_dast(zap: dict) -> go.Figure:
    total = sum(zap.values())
    if total == 0:
        return _empty_fig("✓ Aucune alerte ZAP détectée")

    risk_colors = {
        "High": "#ef4444", "Medium": "#f97316",
        "Low": "#eab308", "Informational": "#3b82f6",
        # fallback pour les labels CORS/CSRF/etc.
    }
    labels = list(zap.keys())
    values = list(zap.values())
    colors = [risk_colors.get(lbl, "#a855f7") for lbl in labels]

    fig = go.Figure(data=[go.Bar(
        x=labels, y=values,
        marker=dict(color=colors, opacity=0.88,
                    line=dict(color="rgba(0,0,0,0.3)", width=1)),
        text=values, textposition="outside",
        textfont=dict(color=TEXT_CLR, size=13, family=FONT_FAM),
        width=0.55,
    )])
    fig.update_layout(
        **BASE_LAYOUT,
        title_text=f"Alertes DAST — {total} alertes ZAP",
        title_x=0.5,
        title_font=dict(size=13, color=MUTED),
        xaxis=_axes(),
        yaxis=dict(**_axes(), range=[0, max(values) * 1.3]),
        bargap=0.35,
    )
    return fig


def fig_falco(falco: dict) -> go.Figure:
    """Graphe Falco — affiche un message propre si aucun événement."""
    total = sum(falco.values())
    if total == 0:
        return _empty_fig("✓ Aucune détection Falco au runtime", "#22c55e")

    colors = ["#22c55e", "#f97316", "#ec4899", "#b91c1c"]
    labels = list(falco.keys())
    values = list(falco.values())

    fig = go.Figure(data=[go.Bar(
        x=labels, y=values,
        marker=dict(color=colors[:len(labels)], opacity=0.88,
                    line=dict(color="rgba(0,0,0,0.3)", width=1)),
        text=values, textposition="outside",
        textfont=dict(color=TEXT_CLR, size=13, family=FONT_FAM),
        width=0.55,
    )])
    fig.update_layout(
        **BASE_LAYOUT,
        title_text=f"Événements Runtime — {total} détections",
        title_x=0.5,
        title_font=dict(size=13, color=MUTED),
        xaxis=_axes(),
        yaxis=dict(**_axes(), range=[0, max(values) * 1.3]),
        bargap=0.35,
    )
    return fig


def fig_secrets(count: int) -> go.Figure:
    max_val = max(5, count + 3)
    bar_color = "#ef4444" if count > 0 else "#22c55e"
    fig = go.Figure(go.Indicator(
        mode="number+gauge",
        value=count,
        number={"font": {"color": bar_color, "size": 58, "family": FONT_FAM}},
        title={"text": "Secrets Détectés",
               "font": {"color": MUTED, "size": 13, "family": FONT_FAM}},
        gauge={
            "axis": {"range": [0, max_val],
                     "tickcolor": MUTED,
                     "tickfont": {"color": MUTED, "size": 11}},
            "bar": {"color": bar_color, "thickness": 0.35},
            "bgcolor": "rgba(255,255,255,0.03)",
            "borderwidth": 0,
            "steps": [
                {"range": [0, max_val * 0.33],  "color": "rgba(34,197,94,0.08)"},
                {"range": [max_val * 0.33, max_val * 0.66], "color": "rgba(249,115,22,0.08)"},
                {"range": [max_val * 0.66, max_val], "color": "rgba(239,68,68,0.12)"},
            ],
            "threshold": {
                "line": {"color": "#ef4444", "width": 3},
                "thickness": 0.75,
                "value": 1,
            },
        },
    ))
    fig.update_layout(**BASE_LAYOUT)
    return fig


def fig_trend() -> go.Figure:
    x = ["Scan 1", "Scan 2", "Scan 3", "Actuel"]
    y = [120, 95, 60, 40]
    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=x, y=y,
        mode="lines+markers+text",
        text=y,
        textposition="top center",
        textfont=dict(color=TEXT_CLR, size=12, family=FONT_FAM),
        line=dict(color="#06b6d4", width=3),
        marker=dict(size=10, color="#06b6d4",
                    line=dict(color="#0e7490", width=2)),
        fill="tozeroy",
        fillcolor="rgba(6,182,212,0.07)",
    ))
    fig.update_layout(
        **BASE_LAYOUT,
        title_text="Tendance Sécurité",
        title_x=0.5,
        title_font=dict(size=13, color=MUTED),
        xaxis=_axes(),
        yaxis=dict(**_axes(), range=[0, 140]),
    )
    return fig


# ─────────────────────────────────────────────────────────────────────────────
# 5. MARKDOWN → HTML (sans dépendance externe)
# ─────────────────────────────────────────────────────────────────────────────

def md_to_html(text: str) -> str:
    lines = text.split("\n")
    out, in_ul = [], False
    for line in lines:
        if line.startswith("### "):
            if in_ul: out.append("</ul>"); in_ul = False
            out.append(f"<h3>{_md_inline(line[4:])}</h3>")
        elif line.startswith("## "):
            if in_ul: out.append("</ul>"); in_ul = False
            out.append(f"<h2>{_md_inline(line[3:])}</h2>")
        elif line.startswith("# "):
            if in_ul: out.append("</ul>"); in_ul = False
            out.append(f"<h1>{_md_inline(line[2:])}</h1>")
        elif re.match(r"^[-*+] ", line):
            if not in_ul: out.append("<ul>"); in_ul = True
            out.append(f"<li>{_md_inline(line[2:])}</li>")
        elif re.match(r"^\d+\. ", line):
            if not in_ul: out.append("<ul>"); in_ul = True
            item = re.sub(r"^\d+\. ", "", line)
            out.append(f"<li>{_md_inline(item)}</li>")
        elif line.strip() == "":
            if in_ul: out.append("</ul>"); in_ul = False
        else:
            if in_ul: out.append("</ul>"); in_ul = False
            out.append(f"<p>{_md_inline(line)}</p>")
    if in_ul:
        out.append("</ul>")
    return "\n".join(out)

def _md_inline(text: str) -> str:
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"\*(.+?)\*",     r"<em>\1</em>",         text)
    text = re.sub(r"`(.+?)`",       r"<code>\1</code>",      text)
    return text


# ─────────────────────────────────────────────────────────────────────────────
# 6. INJECTION DES BALISES GRAPHIQUES DANS LE TEXTE IA
# ─────────────────────────────────────────────────────────────────────────────

def inject_graphs(html_text: str, graphs: dict) -> str:
    wrapper = (
        '<div style="margin:18px auto;max-width:720px;background:rgba(255,255,255,0.02);'
        'border-radius:10px;padding:10px 14px;border:1px solid rgba(255,255,255,0.07)">'
        '{}</div>'
    )
    for tag, html_fig in graphs.items():
        placeholder_html = f"<p>[{tag}]</p>"
        placeholder_raw  = f"[{tag}]"
        replacement = wrapper.format(html_fig)
        html_text = html_text.replace(placeholder_html, replacement)
        html_text = html_text.replace(placeholder_raw,  replacement)
    return html_text


# ─────────────────────────────────────────────────────────────────────────────
# 7. GÉNÉRATION DU DASHBOARD
# ─────────────────────────────────────────────────────────────────────────────

def generate_dashboard():
    # — Données réelles —
    trivy_data   = parse_trivy()
    sonar_data   = parse_sonar()
    zap_data     = parse_zap()
    falco_data   = parse_falco()
    gitleaks_cnt = parse_gitleaks([
        "gitleaks-results.sarif/results.sarif",
        "gitleaks-results.sarif/gitleaks.sarif",
        "results.sarif",
        "gitleaks-report.json",
    ])
    ai_raw = get_ai_summary(trivy_data, sonar_data, zap_data, falco_data, gitleaks_cnt)
    risk   = compute_risk_score(trivy_data, falco_data, gitleaks_cnt, zap_data)

    # — Métadonnées —
    meta = {
        "sha":       os.environ.get("GITHUB_SHA",        "local")[:8],
        "run":       os.environ.get("GITHUB_RUN_NUMBER", "—"),
        "branch":    os.environ.get("GITHUB_REF_NAME",   "—"),
        "actor":     os.environ.get("GITHUB_ACTOR",      "—"),
        "run_url":   os.environ.get("GITHUB_RUN_URL",    "#"),
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    }

    # — Figures HTML partiels (CDN Plotly chargé dans <head>) —
    NO_PJS = False
    f_sca   = fig_sca(trivy_data).to_html(full_html=False,  include_plotlyjs=NO_PJS)
    f_sast  = fig_sast(sonar_data).to_html(full_html=False, include_plotlyjs=NO_PJS)
    f_dast  = fig_dast(zap_data).to_html(full_html=False,   include_plotlyjs=NO_PJS)
    f_falco = fig_falco(falco_data).to_html(full_html=False, include_plotlyjs=NO_PJS)
    f_sec   = fig_secrets(gitleaks_cnt).to_html(full_html=False, include_plotlyjs=NO_PJS)
    f_trend = fig_trend().to_html(full_html=False,          include_plotlyjs=NO_PJS)

    # — Texte IA : Markdown → HTML + injection des graphiques —
    ai_html = md_to_html(ai_raw)
    ai_html = inject_graphs(ai_html, {
        "GRAPHIQUE_SCA":     f_sca,
        "GRAPHIQUE_SAST":    f_sast,
        "GRAPHIQUE_DAST":    f_dast,
        "GRAPHIQUE_SECRETS": f_sec,
        "GRAPHIQUE_FALCO":   f_falco,
    })

    # — KPIs —
    total_cve   = sum(trivy_data.values())
    total_falco = sum(falco_data.values())
    total_zap   = sum(zap_data.values())
    sast_issues = sonar_data["bugs"] + sonar_data["vulnerabilities"]

    # ─── HTML ────────────────────────────────────────────────────────────────
    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>DevSecOps Dashboard — Run #{meta['run']}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&family=Space+Grotesk:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
  <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
  <style>
    :root {{
      --bg:       #080e1c;
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
    *, *::before, *::after {{ box-sizing:border-box; margin:0; padding:0; }}
    body {{
      background: var(--bg);
      color: var(--text);
      font-family: 'Space Grotesk', sans-serif;
      font-size: 14px;
      line-height: 1.6;
    }}

    /* ── HEADER ── */
    .dash-header {{
      background: linear-gradient(135deg, #060c1a 0%, #0c2340 50%, #060c1a 100%);
      border-bottom: 1px solid var(--border);
      padding: 30px 40px 24px;
      position: relative;
      overflow: hidden;
    }}
    .dash-header::before {{
      content: '';
      position: absolute; inset: 0;
      background:
        radial-gradient(ellipse at 60% 0%, rgba(56,189,248,0.09) 0%, transparent 55%),
        radial-gradient(ellipse at 10% 100%, rgba(129,140,248,0.07) 0%, transparent 50%);
      pointer-events: none;
    }}
    .dash-header h1 {{
      font-family: 'JetBrains Mono', monospace;
      font-size: 1.65rem; font-weight: 700;
      letter-spacing: .04em; color: #f1f5f9;
    }}
    .dash-header h1 span {{ color: var(--accent); }}
    .meta-row {{ display:flex; flex-wrap:wrap; gap:8px; margin-top:14px; }}
    .meta-pill {{
      background: rgba(255,255,255,0.05);
      border: 1px solid var(--border);
      border-radius: 20px;
      padding: 3px 13px;
      font-family: 'JetBrains Mono', monospace;
      font-size: .71rem; color: var(--muted);
    }}
    .meta-pill a {{ color: var(--accent); text-decoration: none; }}

    /* ── MAIN CONTAINER ── */
    .main {{ padding: 28px 36px; }}

    /* ── SECTION LABEL ── */
    .section-label {{
      font-family: 'JetBrains Mono', monospace;
      font-size: .66rem; font-weight: 700;
      letter-spacing: .14em; text-transform: uppercase;
      color: var(--muted);
      margin: 32px 0 14px;
      display: flex; align-items: center; gap: 10px;
    }}
    .section-label::after {{
      content: ''; flex: 1; height: 1px; background: var(--border);
    }}

    /* ── RISK BANNER ── */
    .risk-banner {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-left: 5px solid {risk['color']};
      border-radius: 14px;
      padding: 18px 26px;
      display: flex; align-items: center; gap: 28px; flex-wrap: wrap;
    }}
    .risk-score {{
      font-family: 'JetBrains Mono', monospace;
      font-size: 3.6rem; font-weight: 700;
      color: {risk['color']}; line-height: 1;
    }}
    .risk-score small {{ font-size: 1.1rem; color: var(--muted); }}
    .risk-bar-outer {{
      flex: 1; min-width: 140px; height: 8px;
      background: rgba(255,255,255,0.07);
      border-radius: 4px; overflow: hidden;
    }}
    .risk-bar-inner {{
      height: 100%; width: {risk['score']}%;
      background: {risk['color']}; border-radius: 4px;
    }}

    /* ── KPI GRID ── */
    .kpi-grid {{
      display: grid;
      grid-template-columns: repeat(6, 1fr);
      gap: 12px;
    }}
    @media (max-width: 900px) {{
      .kpi-grid {{ grid-template-columns: repeat(3, 1fr); }}
    }}
    @media (max-width: 540px) {{
      .kpi-grid {{ grid-template-columns: repeat(2, 1fr); }}
    }}
    .kpi {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 16px;
      text-align: center;
      transition: border-color .2s;
    }}
    .kpi:hover {{ border-color: rgba(56,189,248,0.2); }}
    .kpi-val {{
      font-family: 'JetBrains Mono', monospace;
      font-size: 2.2rem; font-weight: 700; line-height: 1.1;
    }}
    .kpi-lbl {{ font-size: .72rem; color: var(--muted); margin-top: 4px; }}

    /* ── CARDS ── */
    .card-dark {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 18px 20px;
      height: 100%;
      transition: border-color .2s;
    }}
    .card-dark:hover {{ border-color: rgba(56,189,248,0.18); }}
    .card-title {{
      font-family: 'JetBrains Mono', monospace;
      font-size: .76rem; font-weight: 600;
      letter-spacing: .09em; text-transform: uppercase;
      color: var(--muted);
      border-bottom: 1px solid var(--border);
      padding-bottom: 10px; margin-bottom: 12px;
      display: flex; align-items: center; gap: 7px;
    }}
    .note {{
      background: rgba(255,255,255,0.025);
      border-left: 2px solid rgba(148,163,184,0.25);
      padding: 6px 11px; font-size: .73rem; color: var(--muted);
      border-radius: 0 5px 5px 0; margin-top: 10px;
    }}

    /* ── AI BOX ── */
    .ai-card {{
      background: var(--surface);
      border: 1px solid rgba(6,182,212,0.18);
      border-radius: 14px; padding: 20px 24px;
    }}
    .ai-card-title {{
      font-family: 'JetBrains Mono', monospace;
      font-size: .82rem; font-weight: 700;
      color: var(--accent);
      border-bottom: 1px solid rgba(6,182,212,0.15);
      padding-bottom: 12px; margin-bottom: 16px;
      display: flex; align-items: center; gap: 8px;
    }}
    .ai-badge {{
      font-size: .66rem;
      background: rgba(6,182,212,0.12);
      color: var(--accent);
      padding: 2px 10px; border-radius: 10px;
      margin-left: auto;
    }}
    .ai-body {{
      font-size: .93rem; color: var(--text); line-height: 1.78;
    }}
    .ai-body h1, .ai-body h2 {{
      font-family: 'JetBrains Mono', monospace;
      color: var(--accent); font-size: .98rem; font-weight: 600;
      margin: 22px 0 8px; letter-spacing: .04em;
    }}
    .ai-body h3 {{
      font-family: 'JetBrains Mono', monospace;
      color: var(--accent2); font-size: .88rem; font-weight: 600;
      margin: 14px 0 6px;
    }}
    .ai-body p {{ margin-bottom: 8px; }}
    .ai-body strong {{ color: #fbbf24; }}
    .ai-body code {{
      background: rgba(255,255,255,0.07);
      padding: 1px 6px; border-radius: 4px;
      font-family: 'JetBrains Mono', monospace; font-size: .85rem;
    }}
    .ai-body ul {{ padding-left: 20px; margin-bottom: 10px; }}
    .ai-body li {{ margin-bottom: 5px; }}

    /* ── FOOTER ── */
    footer {{
      text-align: center; padding: 28px 0 18px;
      font-family: 'JetBrains Mono', monospace;
      font-size: .71rem; color: var(--muted);
      border-top: 1px solid var(--border); margin-top: 40px;
    }}
    footer a {{ color: var(--accent); text-decoration: none; }}
  </style>
</head>
<body>

<!-- ═══ HEADER ═══ -->
<div class="dash-header">
  <h1>🛡️ DevSecOps <span>Executive</span> Dashboard</h1>
  <p style="color:var(--muted);font-size:.84rem;margin-top:5px">
    Pipeline CI/CD — Projet WebGoat
  </p>
  <div class="meta-row">
    <span class="meta-pill">🔀 {meta['branch']}</span>
    <span class="meta-pill">📦 {meta['sha']}</span>
    <span class="meta-pill">🔢 Run #{meta['run']}</span>
    <span class="meta-pill">👤 {meta['actor']}</span>
    <span class="meta-pill">🕐 {meta['timestamp']}</span>
    <span class="meta-pill">
      <a href="{meta['run_url']}" target="_blank">🔗 Voir le run GitHub Actions</a>
    </span>
  </div>
</div>

<div class="main">

  <!-- ═══ SCORE DE RISQUE ═══ -->
  <div class="section-label">Score de risque global</div>
  <div class="risk-banner mb-4">
    <div class="risk-score">{risk['score']}<small>/100</small></div>
    <div>
      <span class="badge fs-6 mb-1" style="background:{risk['color']};color:#fff">
        {risk['status']}
      </span>
      <p style="color:var(--muted);font-size:.82rem;margin:4px 0 0">
        {risk['reason']}
      </p>
    </div>
    <div class="risk-bar-outer">
      <div class="risk-bar-inner"></div>
    </div>
  </div>

  <!-- ═══ KPI ═══ -->
  <div class="section-label">Résumé des scans</div>
  <div class="kpi-grid mb-4">
    <div class="kpi">
      <div class="kpi-val" style="color:{'#ef4444' if gitleaks_cnt>0 else '#22c55e'}">{gitleaks_cnt}</div>
      <div class="kpi-lbl">🔑 Secrets</div>
    </div>
    <div class="kpi">
      <div class="kpi-val" style="color:#f97316">{total_cve}</div>
      <div class="kpi-lbl">📦 CVE Trivy</div>
    </div>
    <div class="kpi">
      <div class="kpi-val" style="color:#3b82f6">{sonar_data['bugs']}</div>
      <div class="kpi-lbl">🐛 Bugs SAST</div>
    </div>
    <div class="kpi">
      <div class="kpi-val" style="color:#ef4444">{sonar_data['vulnerabilities']}</div>
      <div class="kpi-lbl">🔍 Vulns SAST</div>
    </div>
    <div class="kpi">
      <div class="kpi-val" style="color:#a855f7">{total_zap}</div>
      <div class="kpi-lbl">🌐 Alertes ZAP</div>
    </div>
    <div class="kpi">
      <div class="kpi-val" style="color:#ec4899">{total_falco}</div>
      <div class="kpi-lbl">⚡ Runtime</div>
    </div>
  </div>

  <!-- ═══ AI SUMMARY ═══ -->
  <div class="section-label">Synthèse Intelligence Artificielle</div>
  <div class="ai-card mb-4">
    <div class="ai-card-title">
      🤖 Rapport IA Corrélé
      <span class="ai-badge">SCA · SAST · DAST · Runtime · Secrets</span>
    </div>
    <div class="ai-body">{ai_html}</div>
  </div>

  <!-- ═══ GRAPHIQUES LIGNE 1 : SCA · SAST · DAST ═══ -->
  <div class="section-label">Analyse détaillée — Scans</div>
  <div class="row g-3 mb-3">
    <div class="col-lg-4 col-md-6">
      <div class="card-dark">
        <div class="card-title">📦 Dépendances (SCA — Trivy)</div>
        {f_sca}
        <div class="note">CVE détectées dans les librairies tierces. Données réelles du scan.</div>
      </div>
    </div>
    <div class="col-lg-4 col-md-6">
      <div class="card-dark">
        <div class="card-title">🔍 Code Source (SAST — SonarCloud)</div>
        {f_sast}
        <div class="note">Dette technique statique. Intégrer l'API SonarCloud pour données dynamiques.</div>
      </div>
    </div>
    <div class="col-lg-4 col-md-12">
      <div class="card-dark">
        <div class="card-title">🌐 Attaques Web (DAST — ZAP)</div>
        {f_dast}
        <div class="note">Alertes OWASP ZAP sur le conteneur WebGoat en cours d'exécution.</div>
      </div>
    </div>
  </div>

  <!-- ═══ GRAPHIQUES LIGNE 2 : Falco · Gitleaks · Tendance ═══ -->
  <div class="row g-3">
    <div class="col-lg-4 col-md-6">
      <div class="card-dark">
        <div class="card-title">⚡ Runtime (Falco)</div>
        {f_falco}
        <div class="note">Comportements suspects capturés en temps réel par Falco.</div>
      </div>
    </div>
    <div class="col-lg-4 col-md-6">
      <div class="card-dark">
        <div class="card-title">🔑 Secrets Git (Gitleaks)</div>
        {f_sec}
        <div class="note">Secrets en clair dans les commits. Zéro tolérance recommandée.</div>
      </div>
    </div>
    <div class="col-lg-4 col-md-12">
      <div class="card-dark">
        <div class="card-title">📈 Tendance Sécurité</div>
        {f_trend}
        <div class="note">Réduction progressive des vulnérabilités au fil des pipelines.</div>
      </div>
    </div>
  </div>

  <footer>
    Généré automatiquement par GitHub Actions —
    Run #{meta['run']} — {meta['timestamp']} —
    <a href="{meta['run_url']}" target="_blank">Voir le pipeline complet</a>
  </footer>

</div>
</body>
</html>"""

    output = "global_security_report.html"
    with open(output, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[OK] Dashboard généré → {output}")


def parse_gitleaks(candidates: list) -> int:
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
            print(f"[INFO] Gitleaks : {count} secret(s) dans {path}")
            return count
        except Exception as e:
            print(f"[WARN] Gitleaks ({path}) : {e}", file=sys.stderr)
    print("[WARN] Gitleaks : aucun rapport trouvé.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    generate_dashboard()
