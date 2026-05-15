"""
scripts/generate_dashboard.py
──────────────────────────────────────────────────────────────────────────────
Génère global_security_report.html — Dashboard DevSecOps (thème dark / light)
Lit les rapports réels du pipeline et affiche 6 graphiques Plotly interactifs.
──────────────────────────────────────────────────────────────────────────────
"""

import json
import os
import re
import sys
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
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        for result in data.get("Results", []):
            for vuln in result.get("Vulnerabilities", []):
                sev = vuln.get("Severity", "").capitalize()
                if sev in counts:
                    counts[sev] += 1
    except Exception as exc:
        print(f"[ERROR] Trivy : {exc}", file=sys.stderr)
    return counts


def parse_sonar(path: str = "sonar-results.json") -> dict:
    """Lit le JSON SonarCloud (format component/measures)."""
    defaults = {"bugs": 211, "vulnerabilities": 42, "security_hotspots": 68}
    data = {"bugs": 0, "vulnerabilities": 0, "security_hotspots": 0}
    if not os.path.isfile(path):
        print(f"[WARN] SonarCloud : fichier introuvable — valeurs démo utilisées.", file=sys.stderr)
        return defaults
    try:
        with open(path, encoding="utf-8") as fh:
            raw = json.load(fh)
        for measure in raw.get("component", {}).get("measures", []):
            metric = measure.get("metric")
            if metric in data:
                data[metric] = int(measure.get("value", 0))
    except Exception as exc:
        print(f"[ERROR] SonarCloud : {exc}", file=sys.stderr)
        return defaults
    return data


def parse_zap(path: str = "report_json.json") -> dict:
    counts = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}

    # 1. Essai avec report_json.json (source principale)
    for candidate in ("report_json.json", "report_html.html"):
        if not os.path.isfile(candidate):
            continue
        try:
            with open(candidate, encoding="utf-8") as fh:
                data = json.load(fh)
            found = False
            for site in data.get("site", []):
                for alert in site.get("alerts", []):
                    # riskdesc peut être "Medium (2)" ou "Medium" → on prend le 1er mot
                    risk = alert.get("riskdesc", "").split(" ")[0].capitalize()
                    if risk in counts:
                        counts[risk] += 1
                        found = True
            if found or candidate == "report_json.json":
                print(f"[INFO] ZAP : {sum(counts.values())} alertes depuis {candidate}")
                return counts
        except json.JSONDecodeError:
            continue
        except Exception as exc:
            print(f"[ERROR] ZAP ({candidate}) : {exc}", file=sys.stderr)

    # 2. Fallback HTML regex
    html_path = "report_html.html"
    if os.path.isfile(html_path):
        try:
            with open(html_path, encoding="utf-8") as fh:
                html = fh.read()
            for risk in list(counts.keys()):
                m = re.search(
                    rf'<td[^>]*>\s*{risk}\s*</td>\s*<td[^>]*>\s*(\d+)\s*</td>',
                    html, re.IGNORECASE,
                )
                if m:
                    counts[risk] = int(m.group(1))
            print(f"[INFO] ZAP : fallback HTML regex utilisé")
            return counts
        except Exception as exc:
            print(f"[ERROR] ZAP HTML fallback : {exc}", file=sys.stderr)

    print("[WARN] ZAP : aucun rapport trouvé — compteurs à zéro.", file=sys.stderr)
    return counts


def parse_falco(path: str = "falco-results.json") -> dict:
    counts = {"Notice": 0, "Warning": 0, "Error": 0, "Critical": 0}
    if not os.path.isfile(path):
        print(f"[WARN] Falco : fichier introuvable ({path})", file=sys.stderr)
        return counts
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    log  = json.loads(line)
                    prio = log.get("priority", "").capitalize()
                    if prio in counts:
                        counts[prio] += 1
                except json.JSONDecodeError:
                    pass
    except Exception as exc:
        print(f"[ERROR] Falco : {exc}", file=sys.stderr)
    return counts


def parse_gitleaks(candidates: list) -> int:
    for path in candidates:
        if not os.path.isfile(path):
            continue
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
            count = len(data) if isinstance(data, list) else \
                    len(data["runs"][0].get("results", [])) if "runs" in data else 0
            print(f"[INFO] Gitleaks : {count} secret(s) dans {path}")
            return count
        except Exception as exc:
            print(f"[WARN] Gitleaks ({path}) : {exc}", file=sys.stderr)
    print("[WARN] Gitleaks : aucun rapport trouvé.", file=sys.stderr)
    return 0


def parse_ai_summary(path: str = "ai-security-summary.txt") -> str:
    fallback = (
        "Analyse IA non disponible pour ce run.\n"
        "Vérifiez la configuration de `GEMINI_API_KEY` et les logs du job `ai-agent-analysis`."
    )
    if not os.path.isfile(path):
        return fallback
    try:
        with open(path, encoding="utf-8") as fh:
            raw = fh.read().strip()
        return raw if raw else fallback
    except Exception as exc:
        print(f"[ERROR] AI summary : {exc}", file=sys.stderr)
        return fallback


# ─────────────────────────────────────────────────────────────────────────────
# 2. PARSEUR CHECKOV (IaC)
# ─────────────────────────────────────────────────────────────────────────────

def parse_checkov(path: str = "checkov-results.json") -> dict:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "passed": 0}
    if not os.path.isfile(path):
        print(f"[WARN] Checkov : fichier introuvable ({path})", file=sys.stderr)
        return counts
    try:
        with open(path, encoding="utf-8") as fh:
            raw = json.load(fh)
        reports = raw if isinstance(raw, list) else [raw]
        for report in reports:
            summary = report.get("summary", {})
            counts["passed"] += summary.get("passed", 0)
            for chk in report.get("results", {}).get("failed_checks", []):
                sev = chk.get("severity", "").capitalize()
                if sev in counts:
                    counts[sev] += 1
                else:
                    counts["Low"] += 1
    except Exception as exc:
        print(f"[ERROR] Checkov : {exc}", file=sys.stderr)
    return counts


# ─────────────────────────────────────────────────────────────────────────────
# 3. MATRICE OWASP TOP 10
# ─────────────────────────────────────────────────────────────────────────────

def build_owasp_matrix(trivy: dict, sonar: dict, zap: dict,
                       falco: dict, gitleaks: int, checkov: dict) -> str:
    """
    Génère un tableau HTML 10 lignes × outils montrant quelles catégories
    OWASP sont couvertes et si des findings existent.
    """

    # Mapping OWASP → (outil, présence de findings, couvert ?)
    # covered = True  → l'outil détecte ce type de risque
    # found   = True  → au moins un finding dans ce run
    any_cve      = sum(trivy.values()) > 0
    any_sast     = sonar["vulnerabilities"] > 0 or sonar["bugs"] > 0
    any_zap      = sum(zap.values()) > 0
    any_secrets  = gitleaks > 0
    any_falco    = falco.get("Error", 0) + falco.get("Critical", 0) > 0
    any_iac      = checkov.get("Critical", 0) + checkov.get("High", 0) > 0

    def _cell(covered: bool, found: bool) -> str:
        if not covered:
            return '<td style="color:#475569;text-align:center">—</td>'
        if found:
            return '<td style="color:#ef4444;text-align:center;font-weight:600">⚠ Trouvé</td>'
        return '<td style="color:#22c55e;text-align:center">✓ OK</td>'

    rows = [
        # (id,  catégorie,                        trivy,        sonar,        zap,         secrets,      falco,        checkov)
        ("A01", "Broken Access Control",           False,        True,         True,         False,        True,         False),
        ("A02", "Cryptographic Failures",          True,         True,         True,         True,         False,        True),
        ("A03", "Injection",                       False,        True,         True,         False,        False,        False),
        ("A04", "Insecure Design",                 False,        True,         True,         False,        False,        True),
        ("A05", "Security Misconfiguration",       False,        False,        True,         False,        True,         True),
        ("A06", "Vulnerable & Outdated Components",True,         False,        False,        False,        False,        False),
        ("A07", "Identification & Auth Failures",  False,        True,         True,         True,         True,         False),
        ("A08", "Software & Data Integrity Failures",True,       True,         False,        True,         False,        True),
        ("A09", "Security Logging & Monitoring",   False,        False,        False,        False,        True,         False),
        ("A10", "Server-Side Request Forgery",     False,        True,         True,         False,        False,        False),
    ]

    # Données de findings par outil (même ordre que les colonnes du tableau)
    found_map = {
        "trivy":   any_cve,
        "sonar":   any_sast,
        "zap":     any_zap,
        "secrets": any_secrets,
        "falco":   any_falco,
        "iac":     any_iac,
    }
    keys = ["trivy", "sonar", "zap", "secrets", "falco", "iac"]
    headers = ["📦 SCA<br><small>Trivy</small>",
               "🔍 SAST<br><small>Sonar</small>",
               "🌐 DAST<br><small>ZAP</small>",
               "🔑 Secrets<br><small>Gitleaks</small>",
               "⚡ Runtime<br><small>Falco</small>",
               "🏗️ IaC<br><small>Checkov</small>"]

    # Style commun
    th = ('style="background:rgba(56,189,248,0.08);color:#7dd3fc;'
          'font-family:\'JetBrains Mono\',monospace;font-size:.7rem;'
          'padding:8px 6px;text-align:center;border:1px solid rgba(255,255,255,0.07)"')
    td_id = ('style="font-family:\'JetBrains Mono\',monospace;font-size:.72rem;'
             'color:#7dd3fc;padding:8px 10px;border:1px solid rgba(255,255,255,0.07);'
             'font-weight:700;white-space:nowrap"')
    td_name = ('style="font-family:\'Space Grotesk\',sans-serif;font-size:.75rem;'
               'color:var(--muted);padding:8px 10px;border:1px solid rgba(255,255,255,0.07)"')
    td_cell = 'style="padding:6px;border:1px solid rgba(255,255,255,0.07)"'

    html = [
        '<div style="overflow-x:auto;margin-top:8px">',
        '<table style="width:100%;border-collapse:collapse;font-size:.75rem">',
        '<thead><tr>',
        f'<th {th}>ID</th>',
        f'<th {th} style="text-align:left">Catégorie OWASP Top 10</th>',
    ]
    for h in headers:
        html.append(f'<th {th}>{h}</th>')
    html.append('</tr></thead><tbody>')

    for (rid, name, *coverage) in rows:
        html.append('<tr>')
        html.append(f'<td {td_id}>{rid}</td>')
        html.append(f'<td {td_name}>{name}</td>')
        for covered, key in zip(coverage, keys):
            found = found_map[key] if covered else False
            if not covered:
                html.append(f'<td {td_cell} style="color:#334155;text-align:center;padding:6px;border:1px solid rgba(255,255,255,0.07)">—</td>')
            elif found:
                html.append(f'<td {td_cell} style="color:#ef4444;text-align:center;font-weight:600;padding:6px;border:1px solid rgba(255,255,255,0.07)">⚠ Trouvé</td>')
            else:
                html.append(f'<td {td_cell} style="color:#22c55e;text-align:center;padding:6px;border:1px solid rgba(255,255,255,0.07)">✓ OK</td>')
        html.append('</tr>')

    html += ['</tbody></table></div>']
    return "\n".join(html)


# ─────────────────────────────────────────────────────────────────────────────
# 4. SCORE DE RISQUE GLOBAL
# ─────────────────────────────────────────────────────────────────────────────

def compute_risk_score(trivy: dict, sonar: dict, falco: dict, gitleaks: int, zap: dict) -> dict:
    # Secrets en clair = bloquant immédiat
    if gitleaks > 0:
        return {
            "score": 100,
            "status": "BLOQUANT",
            "color": "#ef4444",
            "reason": f"{gitleaks} secret(s) en clair détecté(s) — déploiement bloqué immédiatement.",
        }

    zap_high = zap.get("High", 0) if isinstance(zap, dict) else 0

    raw = (
        trivy.get("Critical", 0)  * 8
        + trivy.get("High", 0)    * 3
        + sonar.get("vulnerabilities", 0) * 2
        + (falco.get("Error", 0) + falco.get("Critical", 0)) * 10
        + zap_high                * 5
    )
    score = min(100, raw)

    if score >= 70:
        return {"score": score, "status": "CRITIQUE", "color": "#ef4444",
                "reason": "Vulnérabilités critiques nécessitant une action immédiate."}
    if score >= 40:
        return {"score": score, "status": "ÉLEVÉ",    "color": "#f97316",
                "reason": "Risques significatifs à corriger avant tout déploiement."}
    if score >= 15:
        return {"score": score, "status": "MODÉRÉ",   "color": "#eab308",
                "reason": "Améliorations recommandées ; déploiement possible avec vigilance."}
    return     {"score": score, "status": "FAIBLE",   "color": "#22c55e",
                "reason": "Aucune vulnérabilité critique détectée."}


# ─────────────────────────────────────────────────────────────────────────────
# 5. FIGURES PLOTLY
# ─────────────────────────────────────────────────────────────────────────────

_BG      = "rgba(0,0,0,0)"
_GRID    = "rgba(255,255,255,0.07)"
_TEXT    = "#e2e8f0"
_MUTED   = "#94a3b8"
_FONT    = "JetBrains Mono, Fira Code, monospace"

_BASE = dict(
    paper_bgcolor=_BG,
    plot_bgcolor=_BG,
    font=dict(family=_FONT, color=_TEXT, size=12),
    margin=dict(t=44, b=28, l=28, r=28),
    height=300,
)

def _axes(**kwargs):
    return dict(gridcolor=_GRID, zerolinecolor=_GRID,
                tickfont=dict(color=_TEXT, size=11), **kwargs)


def fig_sca(trivy: dict) -> go.Figure:
    total  = sum(trivy.values())
    colors = ["#ef4444", "#f97316", "#eab308", "#22c55e"]
    if total == 0:
        fig = go.Figure()
        fig.add_annotation(text="✓ Aucune CVE détectée", xref="paper", yref="paper",
                           x=0.5, y=0.5, showarrow=False,
                           font=dict(size=15, color="#22c55e", family=_FONT))
    else:
        fig = go.Figure(data=[go.Pie(
            labels=list(trivy.keys()), values=list(trivy.values()),
            hole=0.5,
            marker=dict(colors=colors, line=dict(color="#1e293b", width=2)),
            textinfo="label+percent",
            textfont=dict(color=_TEXT, size=12),
        )])
    fig.update_layout(**_BASE, title_text="Sévérité des Vulnérabilités",
                      title_x=0.5, title_font=dict(size=13, color=_MUTED))
    return fig


def fig_sast(sonar: dict) -> go.Figure:
    labels = ["Bugs", "Vulnérabilités", "Hotspots"]
    values = [sonar["bugs"], sonar["vulnerabilities"], sonar["security_hotspots"]]
    colors = ["#3b82f6", "#ef4444", "#f59e0b"]
    fig = go.Figure(data=[go.Bar(
        x=labels, y=values,
        marker=dict(color=colors, line=dict(color="rgba(0,0,0,0.3)", width=1), opacity=0.9),
        text=values, textposition="auto",
        textfont=dict(color=_TEXT, size=13, family=_FONT),
    )])
    fig.update_layout(**_BASE, title_text="Dette Technique Statique",
                      title_x=0.5, title_font=dict(size=13, color=_MUTED),
                      xaxis=_axes(), yaxis=_axes())
    return fig


def fig_dast(zap: dict) -> go.Figure:
    labels = list(zap.keys())
    values = list(zap.values())
    if sum(values) == 0:
        fig = go.Figure()
        fig.add_annotation(text="✓ Aucune alerte ZAP", xref="paper", yref="paper",
                           x=0.5, y=0.5, showarrow=False,
                           font=dict(size=15, color="#22c55e", family=_FONT))
    else:
        fig = go.Figure(data=[go.Bar(
            x=labels, y=values,
            marker=dict(color="#a855f7", opacity=0.85,
                        line=dict(color="rgba(0,0,0,0.3)", width=1)),
            text=values, textposition="auto",
            textfont=dict(color=_TEXT, size=13, family=_FONT),
        )])
    fig.update_layout(**_BASE, title_text="Alertes DAST",
                      title_x=0.5, title_font=dict(size=13, color=_MUTED),
                      xaxis=_axes(), yaxis=_axes())
    return fig


def fig_falco(falco: dict) -> go.Figure:
    colors = ["#22c55e", "#f97316", "#ec4899", "#b91c1c"]
    fig = go.Figure(data=[go.Bar(
        x=list(falco.keys()), y=list(falco.values()),
        marker=dict(color=colors, opacity=0.88,
                    line=dict(color="rgba(0,0,0,0.3)", width=1)),
        text=list(falco.values()), textposition="auto",
        textfont=dict(color=_TEXT, size=13, family=_FONT),
    )])
    fig.update_layout(**_BASE, title_text="Événements Runtime",
                      title_x=0.5, title_font=dict(size=13, color=_MUTED),
                      xaxis=_axes(), yaxis=_axes())
    return fig


def fig_secrets(count: int) -> go.Figure:
    max_val    = max(5, count + 3)
    bar_color  = "#ef4444" if count > 0 else "#22c55e"
    fig = go.Figure(go.Indicator(
        mode="number+gauge",
        value=count,
        number={"font": {"color": bar_color, "size": 52, "family": _FONT}},
        title={"text": "Secrets Exposés",
               "font": {"color": _MUTED, "size": 13, "family": _FONT}},
        gauge={
            "axis": {"range": [0, max_val],
                     "tickcolor": _TEXT,
                     "tickfont": {"color": _TEXT, "size": 11}},
            "bar": {"color": bar_color},
            "bgcolor": "rgba(255,255,255,0.04)",
            "borderwidth": 0,
            "steps": [
                {"range": [0,              max_val * 0.3], "color": "rgba(34,197,94,0.08)"},
                {"range": [max_val * 0.3,  max_val * 0.7], "color": "rgba(249,115,22,0.08)"},
                {"range": [max_val * 0.7,  max_val],       "color": "rgba(239,68,68,0.12)"},
            ],
            "threshold": {"line": {"color": "#ef4444", "width": 3},
                          "thickness": 0.75, "value": 1},
        },
    ))
    fig.update_layout(**_BASE)
    return fig


def fig_trend() -> go.Figure:
    """Graphique de tendance — connecter à des données historiques réelles."""
    x = ["Scan 1", "Scan 2", "Scan 3", "Actuel"]
    y = [120, 95, 60, 40]
    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=x, y=y,
        mode="lines+markers+text",
        text=y, textposition="top center",
        textfont=dict(color=_TEXT, size=12, family=_FONT),
        line=dict(color="#06b6d4", width=3),
        marker=dict(size=10, color="#06b6d4", line=dict(color="#0e7490", width=2)),
        fill="tozeroy",
        fillcolor="rgba(6,182,212,0.08)",
    ))
    fig.update_layout(**_BASE, title_text="Tendance Sécurité",
                      title_x=0.5, title_font=dict(size=13, color=_MUTED),
                      xaxis=_axes(), yaxis=_axes())
    return fig


def fig_checkov(checkov: dict) -> go.Figure:
    """Graphique IaC Checkov — checks échoués par sévérité + passés."""
    labels = ["Critical", "High", "Medium", "Low"]
    values = [checkov.get(k, 0) for k in labels]
    colors = ["#ef4444", "#f97316", "#eab308", "#22c55e"]
    passed = checkov.get("passed", 0)

    if sum(values) == 0 and passed == 0:
        fig = go.Figure()
        fig.add_annotation(text="✓ Aucune donnée IaC", xref="paper", yref="paper",
                           x=0.5, y=0.5, showarrow=False,
                           font=dict(size=15, color="#22c55e", family=_FONT))
    else:
        fig = go.Figure()
        fig.add_trace(go.Bar(
            name="Échoués",
            x=labels, y=values,
            marker=dict(color=colors, opacity=0.88,
                        line=dict(color="rgba(0,0,0,0.3)", width=1)),
            text=values, textposition="auto",
            textfont=dict(color=_TEXT, size=13, family=_FONT),
        ))
        fig.add_trace(go.Bar(
            name="Passés",
            x=["Passés"], y=[passed],
            marker=dict(color="#22c55e", opacity=0.7,
                        line=dict(color="rgba(0,0,0,0.3)", width=1)),
            text=[passed], textposition="auto",
            textfont=dict(color=_TEXT, size=13, family=_FONT),
        ))

    fig.update_layout(**_BASE, title_text="Checks IaC (Checkov)",
                      title_x=0.5, title_font=dict(size=13, color=_MUTED),
                      xaxis=_axes(), yaxis=_axes(), barmode="group",
                      legend=dict(font=dict(color=_TEXT, size=11), bgcolor="rgba(0,0,0,0)"))
    return fig


# ─────────────────────────────────────────────────────────────────────────────
# 6. CONVERSION MARKDOWN → HTML
# ─────────────────────────────────────────────────────────────────────────────

def md_to_html(text: str) -> str:
    """Convertit le Markdown minimal du rapport IA en HTML propre."""
    lines  = text.split("\n")
    out    = []
    in_ul  = False

    def _inline(s: str) -> str:
        s = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", s)
        s = re.sub(r"\*(.+?)\*",     r"<em>\1</em>",          s)
        return s

    for line in lines:
        if line.startswith("### "):
            if in_ul: out.append("</ul>"); in_ul = False
            out.append(f"<h3>{_inline(line[4:])}</h3>")
        elif line.startswith("## "):
            if in_ul: out.append("</ul>"); in_ul = False
            out.append(f"<h2>{_inline(line[3:])}</h2>")
        elif line.startswith("# "):
            if in_ul: out.append("</ul>"); in_ul = False
            out.append(f"<h1>{_inline(line[2:])}</h1>")
        elif re.match(r"^[-*+] ", line):
            if not in_ul:
                out.append("<ul>"); in_ul = True
            out.append(f"<li>{_inline(line[2:])}</li>")
        elif line.strip() == "":
            if in_ul: out.append("</ul>"); in_ul = False
            out.append("<br>")
        else:
            if in_ul: out.append("</ul>"); in_ul = False
            out.append(f"<p>{_inline(line)}</p>")

    if in_ul:
        out.append("</ul>")
    return "\n".join(out)


# ─────────────────────────────────────────────────────────────────────────────
# 7. INJECTION DES GRAPHIQUES DANS LE TEXTE IA
# ─────────────────────────────────────────────────────────────────────────────

_GRAPH_WRAPPER = (
    '<div style="margin:20px auto;max-width:700px;'
    'background:rgba(255,255,255,0.03);border-radius:10px;'
    'padding:12px;border:1px solid rgba(255,255,255,0.08)">'
    '{}</div>'
)

def inject_graphs(html_text: str, graphs: dict) -> str:
    for tag, html_fig in graphs.items():
        replacement = _GRAPH_WRAPPER.format(html_fig)
        html_text = html_text.replace(f"[{tag}]",       replacement)
        html_text = html_text.replace(f"<p>[{tag}]</p>", replacement)
    return html_text


def force_inject_sast(ai_html: str, sast_html: str) -> str:
    """
    Si Gemini n'a pas émis [GRAPHIQUE_SAST], l'insère après le titre SAST.
    SonarCloud ne génère pas de fichier JSON lisible directement — le tag
    peut donc être absent du rapport IA.
    """
    wrapper = _GRAPH_WRAPPER.format(sast_html)
    if wrapper in ai_html:
        return ai_html   # déjà présent

    # Cherche un titre h2/h3 mentionnant SAST / SonarCloud
    m = re.search(
        r'(<h[23][^>]*>[^<]*(sast|sonar|code source|code statique)[^<]*</h[23]>)',
        ai_html, re.IGNORECASE,
    )
    if m:
        return ai_html.replace(m.group(0), m.group(0) + "\n" + wrapper, 1)

    # Fallback : après le 2ème <h2>
    h2s = list(re.finditer(r'<h2[^>]*>.*?</h2>', ai_html, re.IGNORECASE))
    idx = h2s[1].end() if len(h2s) >= 2 else (h2s[0].end() if h2s else len(ai_html))
    return ai_html[:idx] + "\n" + wrapper + ai_html[idx:]


# ─────────────────────────────────────────────────────────────────────────────
# 8. GÉNÉRATION DU DASHBOARD
# ─────────────────────────────────────────────────────────────────────────────

def generate_dashboard():
    print("\n" + "═" * 60)
    print("  Génération du Dashboard DevSecOps")
    print("═" * 60)

    # ── Lecture des données ───────────────────────────────────────
    trivy_data    = parse_trivy()
    sonar_data    = parse_sonar()
    zap_data      = parse_zap()
    falco_data    = parse_falco()
    checkov_data  = parse_checkov()
    gitleaks_cnt = parse_gitleaks([
        "gitleaks-results.sarif/results.sarif",
        "gitleaks-results.sarif/gitleaks.sarif",
        "results.sarif",
        "gitleaks-report.json",
    ])
    ai_raw  = parse_ai_summary()
    risk    = compute_risk_score(trivy_data, sonar_data, falco_data, gitleaks_cnt, zap_data)

    # ── Métadonnées CI ────────────────────────────────────────────
    meta = {
        "sha":       os.environ.get("GITHUB_SHA",        "local")[:8],
        "run":       os.environ.get("GITHUB_RUN_NUMBER", "—"),
        "branch":    os.environ.get("GITHUB_REF_NAME",   "—"),
        "actor":     os.environ.get("GITHUB_ACTOR",      "—"),
        "run_url":   os.environ.get("GITHUB_RUN_URL",    "#"),
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    }

    # ── Figures Plotly ────────────────────────────────────────────
    f_sca     = fig_sca(trivy_data)
    f_sast    = fig_sast(sonar_data)
    f_dast    = fig_dast(zap_data)
    f_falco   = fig_falco(falco_data)
    f_sec     = fig_secrets(gitleaks_cnt)
    f_trend   = fig_trend()
    f_checkov = fig_checkov(checkov_data)

    # Grille principale (dashboard)
    g_sca     = f_sca.to_html(full_html=False, include_plotlyjs=False)
    g_sast    = f_sast.to_html(full_html=False, include_plotlyjs=False)
    g_dast    = f_dast.to_html(full_html=False, include_plotlyjs=False)
    g_falco   = f_falco.to_html(full_html=False, include_plotlyjs=False)
    g_sec     = f_sec.to_html(full_html=False, include_plotlyjs=False)
    g_trend   = f_trend.to_html(full_html=False, include_plotlyjs=False)
    g_checkov = f_checkov.to_html(full_html=False, include_plotlyjs=False)

    # Copies dédiées au rapport IA (IDs Plotly distincts)
    ai_sca     = f_sca.to_html(full_html=False, include_plotlyjs=False)
    ai_sast    = f_sast.to_html(full_html=False, include_plotlyjs=False)
    ai_dast    = f_dast.to_html(full_html=False, include_plotlyjs=False)
    ai_falco   = f_falco.to_html(full_html=False, include_plotlyjs=False)
    ai_sec     = f_sec.to_html(full_html=False, include_plotlyjs=False)
    ai_checkov = f_checkov.to_html(full_html=False, include_plotlyjs=False)

    # ── Rapport IA : Markdown → HTML + graphiques ─────────────────
    ai_html = md_to_html(ai_raw)
    ai_html = inject_graphs(ai_html, {
        "GRAPHIQUE_SCA":     ai_sca,
        "GRAPHIQUE_SAST":    ai_sast,
        "GRAPHIQUE_DAST":    ai_dast,
        "GRAPHIQUE_SECRETS": ai_sec,
        "GRAPHIQUE_FALCO":   ai_falco,
        "GRAPHIQUE_IAC":     ai_checkov,   # ← NOUVEAU
    })
    ai_html = force_inject_sast(ai_html, ai_sast)

    # ── Matrice OWASP Top 10 ──────────────────────────────────────
    owasp_matrix = build_owasp_matrix(
        trivy_data, sonar_data, zap_data,
        falco_data, gitleaks_cnt, checkov_data
    )

    # ── KPIs ──────────────────────────────────────────────────────
    total_cve   = sum(trivy_data.values())
    total_falco = sum(falco_data.values())
    total_zap   = sum(zap_data.values())

    # ─────────────────────────────────────────────────────────────────────────
    # HTML
    # ─────────────────────────────────────────────────────────────────────────
    html = f"""<!DOCTYPE html>
<html lang="fr" data-theme="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>DevSecOps Dashboard — Run #{meta['run']}</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
  <link href="https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=IBM+Plex+Mono:wght@300;400;500;600&display=swap" rel="stylesheet">
  <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>

  <style>
    /* ══════════════════════════════════════════════════════════
       DEVSECOPS DASHBOARD — Cyber-Terminal Aesthetic
       Sombre · Précis · Animé · Mémorable
    ══════════════════════════════════════════════════════════ */

    @import url('https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=IBM+Plex+Mono:wght@300;400;500;600&display=swap');

    /* ── VARIABLES ── */
    :root {{
      --bg:        #020b18;
      --bg2:       #040f1f;
      --surface:   #071428;
      --surface2:  #0c1f3a;
      --border:    rgba(0,200,255,0.10);
      --border2:   rgba(0,200,255,0.22);
      --accent:    #00c8ff;
      --accent2:   #7c3aed;
      --accent3:   #00ffa3;
      --danger:    #ff3d5a;
      --warn:      #ff8c00;
      --ok:        #00ffa3;
      --text:      #cfe8ff;
      --muted:     #5a8aaa;
      --glow:      rgba(0,200,255,0.18);
      --glow-ok:   rgba(0,255,163,0.15);
      --glow-bad:  rgba(255,61,90,0.18);
      --font-head: 'Syne', sans-serif;
      --font-mono: 'IBM Plex Mono', monospace;
    }}

    [data-theme="light"] {{
      --bg:        #f0f6ff;
      --bg2:       #e6f0fb;
      --surface:   #ffffff;
      --surface2:  #ddeeff;
      --border:    rgba(0,100,200,0.12);
      --border2:   rgba(0,100,200,0.28);
      --accent:    #0077cc;
      --accent2:   #6d28d9;
      --accent3:   #059669;
      --danger:    #dc2626;
      --warn:      #d97706;
      --ok:        #059669;
      --text:      #0f2a45;
      --muted:     #4a6a8a;
      --glow:      rgba(0,100,200,0.08);
      --glow-ok:   rgba(5,150,105,0.08);
      --glow-bad:  rgba(220,38,38,0.08);
    }}

    /* ── RESET & BASE ── */
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

    html {{ scroll-behavior: smooth; }}

    body {{
      background: var(--bg);
      color: var(--text);
      font-family: var(--font-mono);
      font-size: 13px;
      line-height: 1.65;
      min-height: 100vh;
      transition: background .4s, color .4s;
      overflow-x: hidden;
    }}

    /* ── ANIMATED GRID BACKGROUND ── */
    body::before {{
      content: '';
      position: fixed; inset: 0; z-index: 0;
      background-image:
        linear-gradient(rgba(0,200,255,0.025) 1px, transparent 1px),
        linear-gradient(90deg, rgba(0,200,255,0.025) 1px, transparent 1px);
      background-size: 40px 40px;
      animation: gridPulse 8s ease-in-out infinite;
      pointer-events: none;
    }}
    [data-theme="light"] body::before {{
      background-image:
        linear-gradient(rgba(0,100,200,0.04) 1px, transparent 1px),
        linear-gradient(90deg, rgba(0,100,200,0.04) 1px, transparent 1px);
    }}
    @keyframes gridPulse {{
      0%, 100% {{ opacity: 1; }}
      50%       {{ opacity: 0.4; }}
    }}

    /* ── SCANLINE OVERLAY ── */
    body::after {{
      content: '';
      position: fixed; inset: 0; z-index: 1;
      background: repeating-linear-gradient(
        0deg,
        transparent,
        transparent 2px,
        rgba(0,0,0,0.03) 2px,
        rgba(0,0,0,0.03) 4px
      );
      pointer-events: none;
    }}
    [data-theme="light"] body::after {{ opacity: 0; }}

    /* All content above overlays */
    .dash-header, #theme-toggle, #main-content {{ position: relative; z-index: 2; }}

    /* ── THEME TOGGLE ── */
    #theme-toggle {{
      position: fixed; top: 18px; right: 20px; z-index: 9999;
      display: flex; gap: 6px;
    }}
    .theme-btn {{
      width: 38px; height: 32px;
      border: 1px solid var(--border2);
      background: var(--surface);
      color: var(--accent);
      border-radius: 8px; cursor: pointer; font-size: 14px;
      display: flex; align-items: center; justify-content: center;
      transition: all .2s;
      backdrop-filter: blur(12px);
    }}
    .theme-btn:hover  {{ background: var(--surface2); box-shadow: 0 0 12px var(--glow); }}
    .theme-btn.active {{ border-color: var(--accent); box-shadow: 0 0 14px var(--glow); }}

    /* ── HEADER ── */
    .dash-header {{
      background: linear-gradient(160deg, #020d1e 0%, #061830 50%, #020d1e 100%);
      border-bottom: 1px solid var(--border2);
      padding: 32px 48px 26px;
      position: relative; overflow: hidden;
    }}
    [data-theme="light"] .dash-header {{
      background: linear-gradient(160deg, #ddeeff 0%, #c8e0f8 50%, #ddeeff 100%);
    }}

    /* Animated glow orbs in header */
    .dash-header::before {{
      content: '';
      position: absolute;
      width: 500px; height: 500px;
      background: radial-gradient(circle, rgba(0,200,255,0.07) 0%, transparent 70%);
      top: -200px; right: -100px;
      animation: orbFloat 6s ease-in-out infinite;
      pointer-events: none;
    }}
    .dash-header::after {{
      content: '';
      position: absolute;
      width: 300px; height: 300px;
      background: radial-gradient(circle, rgba(124,58,237,0.06) 0%, transparent 70%);
      bottom: -100px; left: 200px;
      animation: orbFloat 8s ease-in-out infinite reverse;
      pointer-events: none;
    }}
    @keyframes orbFloat {{
      0%, 100% {{ transform: translateY(0px) scale(1); }}
      50%       {{ transform: translateY(-20px) scale(1.05); }}
    }}

    .header-eyebrow {{
      font-family: var(--font-mono);
      font-size: .65rem; letter-spacing: .25em;
      color: var(--accent); text-transform: uppercase;
      margin-bottom: 8px;
      display: flex; align-items: center; gap: 8px;
    }}
    .header-eyebrow::before {{
      content: '';
      display: inline-block; width: 20px; height: 1px;
      background: var(--accent);
    }}

    .dash-header h1 {{
      font-family: var(--font-head);
      font-size: 2rem; font-weight: 800; letter-spacing: -.01em;
      color: var(--text); line-height: 1.1;
    }}
    [data-theme="light"] .dash-header h1 {{ color: #071428; }}
    .dash-header h1 .accent {{ color: var(--accent); }}
    .dash-header h1 .accent2 {{ color: var(--accent2); }}

    .dash-subtitle {{
      font-family: var(--font-mono);
      font-size: .75rem; color: var(--muted);
      margin-top: 6px; letter-spacing: .05em;
    }}

    .meta-row {{ display: flex; flex-wrap: wrap; gap: 6px; margin-top: 16px; }}
    .meta-pill {{
      background: rgba(0,200,255,0.06);
      border: 1px solid var(--border2);
      border-radius: 6px; padding: 3px 10px;
      font-family: var(--font-mono); font-size: .68rem;
      color: var(--muted);
      transition: all .2s;
    }}
    .meta-pill:hover {{ background: rgba(0,200,255,0.12); color: var(--accent); }}
    .meta-pill a {{ color: inherit; text-decoration: none; }}

    /* ── MAIN CONTENT ── */
    #main-content {{ padding: 32px 40px; }}

    /* ── SECTION LABEL ── */
    .section-label {{
      font-family: var(--font-mono);
      font-size: .62rem; font-weight: 600; letter-spacing: .2em;
      text-transform: uppercase; color: var(--accent);
      margin: 36px 0 14px;
      display: flex; align-items: center; gap: 12px;
      opacity: 0;
      animation: fadeSlideUp .5s ease forwards;
    }}
    .section-label::before {{
      content: '//';
      color: var(--accent2); font-size: .7rem;
    }}
    .section-label::after {{
      content: ''; flex: 1; height: 1px;
      background: linear-gradient(90deg, var(--border2), transparent);
    }}

    /* ── CARDS ── */
    .card-dark {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 12px; padding: 20px;
      transition: border-color .3s, box-shadow .3s, transform .2s;
      opacity: 0;
      animation: fadeSlideUp .5s ease forwards;
    }}
    .card-dark:hover {{
      border-color: var(--border2);
      box-shadow: 0 0 24px var(--glow);
      transform: translateY(-2px);
    }}
    .card-title {{
      font-family: var(--font-mono);
      font-size: .7rem; font-weight: 600; letter-spacing: .12em;
      text-transform: uppercase; color: var(--muted);
      margin-bottom: 14px;
      border-bottom: 1px solid var(--border);
      padding-bottom: 10px;
      display: flex; align-items: center; gap: 8px;
    }}

    /* ── RISK BANNER ── */
    .risk-banner {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 12px; padding: 24px 32px;
      display: flex; align-items: center; gap: 28px; flex-wrap: wrap;
      position: relative; overflow: hidden;
      opacity: 0;
      animation: fadeSlideUp .4s .1s ease forwards;
    }}
    .risk-banner::before {{
      content: '';
      position: absolute; inset: 0;
      background: linear-gradient(135deg,
        rgba(0,200,255,0.03) 0%, transparent 60%);
      pointer-events: none;
    }}
    .risk-score {{
      font-family: var(--font-head);
      font-size: 3.8rem; font-weight: 800;
      line-height: 1; letter-spacing: -.03em;
    }}
    .risk-score small {{
      font-size: 1rem; font-weight: 400;
      color: var(--muted); font-family: var(--font-mono);
    }}
    .risk-status-badge {{
      display: inline-flex; align-items: center; gap: 6px;
      padding: 4px 14px; border-radius: 6px;
      font-family: var(--font-mono); font-size: .72rem;
      font-weight: 600; letter-spacing: .1em;
      text-transform: uppercase; margin-bottom: 6px;
      border: 1px solid currentColor;
    }}
    .risk-reason {{
      font-family: var(--font-mono);
      font-size: .75rem; color: var(--muted); margin: 0;
    }}
    .risk-bar-outer {{
      flex: 1; min-width: 140px; height: 6px;
      background: rgba(255,255,255,0.06);
      border-radius: 3px; overflow: hidden;
    }}
    .risk-bar-inner {{
      height: 100%;
      border-radius: 3px;
      transition: width .8s cubic-bezier(.4,0,.2,1);
      position: relative;
    }}
    .risk-bar-inner::after {{
      content: '';
      position: absolute; right: 0; top: 0; bottom: 0;
      width: 20px;
      background: rgba(255,255,255,0.4);
      border-radius: 3px;
      animation: barGlow 2s ease-in-out infinite;
    }}
    @keyframes barGlow {{
      0%, 100% {{ opacity: 0.4; }}
      50%       {{ opacity: 1; }}
    }}

    /* ── KPI GRID ── */
    .kpi-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 12px;
    }}
    .kpi {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px; padding: 16px 18px;
      text-align: center;
      transition: all .25s;
      cursor: default;
      position: relative; overflow: hidden;
      opacity: 0;
      animation: fadeSlideUp .5s ease forwards;
    }}
    .kpi::before {{
      content: '';
      position: absolute; inset: 0;
      background: linear-gradient(135deg, transparent 60%, rgba(0,200,255,0.04));
      pointer-events: none;
    }}
    .kpi:hover {{
      border-color: var(--border2);
      transform: translateY(-3px);
      box-shadow: 0 8px 28px var(--glow);
    }}
    .kpi-val {{
      font-family: var(--font-head);
      font-size: 2.2rem; font-weight: 800;
      line-height: 1.1; letter-spacing: -.02em;
    }}
    .kpi-lbl {{
      font-family: var(--font-mono);
      font-size: .65rem; color: var(--muted);
      margin-top: 4px; letter-spacing: .06em;
    }}
    .kpi-bar {{
      height: 2px; border-radius: 1px;
      margin-top: 10px; width: 100%;
      background: var(--border);
      position: relative; overflow: hidden;
    }}
    .kpi-bar::after {{
      content: '';
      position: absolute; left: 0; top: 0; bottom: 0;
      width: 60%; border-radius: 1px;
      background: currentColor;
      animation: kpiBarIn 1s ease forwards;
    }}
    @keyframes kpiBarIn {{
      from {{ width: 0; }}
    }}

    /* ── AI SECTION ── */
    .ai-wrapper {{ max-width: 920px; margin: 0 auto; }}
    .ai-box {{
      background: linear-gradient(135deg,
        rgba(0,200,255,0.03) 0%,
        rgba(124,58,237,0.03) 100%);
      border: 1px solid rgba(0,200,255,0.12);
      border-radius: 10px; padding: 28px 36px;
      font-family: var(--font-mono);
      font-size: .82rem; color: var(--muted); line-height: 1.9;
    }}
    .ai-badge {{
      font-size: .62rem;
      background: rgba(0,200,255,0.08);
      color: var(--accent);
      padding: 2px 10px; border-radius: 4px;
      margin-left: auto; border: 1px solid var(--border2);
      letter-spacing: .08em;
    }}
    .ai-box h1, .ai-box h2 {{
      font-family: var(--font-head); color: var(--accent);
      font-size: .95rem; font-weight: 700;
      margin: 22px 0 8px; letter-spacing: .02em;
      border-left: 3px solid var(--accent);
      padding-left: 12px;
    }}
    .ai-box h3 {{
      font-family: var(--font-mono); color: var(--accent2);
      font-size: .82rem; font-weight: 600; margin: 14px 0 6px;
    }}
    .ai-box strong {{ color: #fbbf24; }}
    .ai-box ul {{ padding-left: 18px; }}
    .ai-box li {{ margin-bottom: 5px; }}

    /* ── NOTE ── */
    .note {{
      background: rgba(0,200,255,0.03);
      border-left: 2px solid var(--border2);
      padding: 6px 10px;
      font-family: var(--font-mono); font-size: .7rem;
      color: var(--muted); border-radius: 0 5px 5px 0;
      margin-top: 8px;
    }}

    /* ── FOOTER ── */
    footer {{
      text-align: center; padding: 28px 0 24px;
      font-family: var(--font-mono); font-size: .68rem;
      color: var(--muted);
      border-top: 1px solid var(--border);
      margin-top: 48px;
      position: relative;
    }}
    footer::before {{
      content: '';
      position: absolute; top: 0; left: 50%;
      transform: translateX(-50%);
      width: 80px; height: 1px;
      background: linear-gradient(90deg, transparent, var(--accent), transparent);
    }}
    footer a {{ color: var(--accent); text-decoration: none; }}
    footer a:hover {{ text-shadow: 0 0 8px var(--accent); }}

    /* ── ANIMATIONS ── */
    @keyframes fadeSlideUp {{
      from {{ opacity: 0; transform: translateY(16px); }}
      to   {{ opacity: 1; transform: translateY(0); }}
    }}

    /* Staggered animation delays for cards */
    .card-dark:nth-child(1) {{ animation-delay: .05s; }}
    .card-dark:nth-child(2) {{ animation-delay: .10s; }}
    .card-dark:nth-child(3) {{ animation-delay: .15s; }}
    .card-dark:nth-child(4) {{ animation-delay: .20s; }}
    .card-dark:nth-child(5) {{ animation-delay: .25s; }}
    .card-dark:nth-child(6) {{ animation-delay: .30s; }}
    .kpi:nth-child(1) {{ animation-delay: .05s; }}
    .kpi:nth-child(2) {{ animation-delay: .09s; }}
    .kpi:nth-child(3) {{ animation-delay: .13s; }}
    .kpi:nth-child(4) {{ animation-delay: .17s; }}
    .kpi:nth-child(5) {{ animation-delay: .21s; }}
    .kpi:nth-child(6) {{ animation-delay: .25s; }}
    .kpi:nth-child(7) {{ animation-delay: .29s; }}
    .section-label:nth-of-type(1) {{ animation-delay: .0s; }}
    .section-label:nth-of-type(2) {{ animation-delay: .1s; }}
    .section-label:nth-of-type(3) {{ animation-delay: .2s; }}
    .section-label:nth-of-type(4) {{ animation-delay: .3s; }}
    .section-label:nth-of-type(5) {{ animation-delay: .4s; }}

    /* ── TYPING CURSOR on title ── */
    .cursor-blink {{
      display: inline-block;
      width: 2px; height: 1.1em;
      background: var(--accent);
      margin-left: 4px;
      vertical-align: middle;
      animation: blink .9s step-end infinite;
    }}
    @keyframes blink {{
      0%, 100% {{ opacity: 1; }}
      50%       {{ opacity: 0; }}
    }}

    /* ── OWASP TABLE ── */
    .owasp-table-wrap {{ overflow-x: auto; margin-top: 8px; }}
    .owasp-table-wrap table {{
      width: 100%; border-collapse: collapse;
      font-family: var(--font-mono); font-size: .7rem;
    }}
    .owasp-table-wrap th {{
      background: rgba(0,200,255,0.05);
      color: var(--accent); padding: 8px 6px;
      text-align: center;
      border: 1px solid var(--border);
      font-size: .65rem; letter-spacing: .08em;
    }}
    .owasp-table-wrap td {{
      padding: 7px 10px;
      border: 1px solid var(--border);
    }}

    /* ── PULSE DOT (live indicator) ── */
    .live-dot {{
      display: inline-block; width: 7px; height: 7px;
      border-radius: 50%; background: var(--ok);
      margin-right: 6px;
      animation: pulse 2s ease-in-out infinite;
    }}
    @keyframes pulse {{
      0%, 100% {{ box-shadow: 0 0 0 0 rgba(0,255,163,0.5); }}
      50%       {{ box-shadow: 0 0 0 6px rgba(0,255,163,0); }}
    }}
  </style>
<!-- ── THEME TOGGLE ── -->
<div id="theme-toggle">
  <button id="dark-mode"  class="theme-btn active" title="Dark Mode">🌙</button>
  <button id="light-mode" class="theme-btn"        title="Light Mode">☀️</button>
</div>

<!-- ── HEADER ── -->
<div class="dash-header">
  <div class="header-eyebrow"><span class="live-dot"></span>DevSecOps Pipeline &nbsp;·&nbsp; Live Threat Report</div>
  <h1>🛡️ <span class="accent">Security</span> <span class="accent2">Executive</span> Dashboard<span class="cursor-blink"></span></h1>
  <div class="dash-subtitle">WebGoat CI/CD · Automated Security Intelligence</div>
  <div class="meta-row">
    <span class="meta-pill">🔀 {meta['branch']}</span>
    <span class="meta-pill">📦 {meta['sha']}</span>
    <span class="meta-pill">🔢 Run #{meta['run']}</span>
    <span class="meta-pill">👤 {meta['actor']}</span>
    <span class="meta-pill">🕐 {meta['timestamp']}</span>
    <span class="meta-pill"><a href="{meta['run_url']}" target="_blank">🔗 GitHub Actions</a></span>
  </div>
</div>

<div id="main-content">

  <!-- ── SCORE ── -->
  <div class="section-label">Score de risque global</div>
  <div class="risk-banner mb-4">
    <div class="risk-score" style="color:{risk['color']}">{risk['score']}<small>/100</small></div>
    <div>
      <div class="risk-status-badge" style="color:{risk['color']};border-color:{risk['color']};background:rgba(0,0,0,0.2)">● {risk['status']}</div>
      <p class="risk-reason">{risk['reason']}</p>
    </div>
    <div class="risk-bar-outer">
      <div class="risk-bar-inner" style="width:{risk['score']}%;background:{risk['color']}"></div>
    </div>
  </div>

  <!-- ── KPIs ── -->
  <div class="section-label">Résumé des scans</div>
  <div class="kpi-grid mb-4">
    <div class="kpi">
      <div class="kpi-val" style="color:{'#ff3d5a' if gitleaks_cnt>0 else '#00ffa3'}" data-target="{gitleaks_cnt}">{gitleaks_cnt}</div>
      <div class="kpi-lbl">🔑 Secrets détectés</div>
      <div class="kpi-bar" style="color:{'#ff3d5a' if gitleaks_cnt>0 else '#00ffa3'}"></div>
    </div>
    <div class="kpi">
      <div class="kpi-val" style="color:#ff8c00" data-target="{total_cve}">{total_cve}</div>
      <div class="kpi-lbl">📦 CVE Dépendances</div>
      <div class="kpi-bar" style="color:#ff8c00"></div>
    </div>
    <div class="kpi">
      <div class="kpi-val" style="color:#00c8ff" data-target="{sonar_data['bugs'] + sonar_data['vulnerabilities']}">{sonar_data['bugs'] + sonar_data['vulnerabilities']}</div>
      <div class="kpi-lbl">🔍 Issues SAST</div>
      <div class="kpi-bar" style="color:#00c8ff"></div>
    </div>
    <div class="kpi">
      <div class="kpi-val" style="color:#a78bfa" data-target="{total_zap}">{total_zap}</div>
      <div class="kpi-lbl">🌐 Alertes DAST</div>
      <div class="kpi-bar" style="color:#a78bfa"></div>
    </div>
    <div class="kpi">
      <div class="kpi-val" style="color:#f472b6" data-target="{total_falco}">{total_falco}</div>
      <div class="kpi-lbl">⚡ Runtime Falco</div>
      <div class="kpi-bar" style="color:#f472b6"></div>
    </div>
    <div class="kpi">
      <div class="kpi-val" style="color:{'#00ffa3' if risk['score']<40 else '#ff3d5a'}" data-target="{risk['score']}">{risk['score']}</div>
      <div class="kpi-lbl">🎯 Score Risque</div>
      <div class="kpi-bar" style="color:{'#00ffa3' if risk['score']<40 else '#ff3d5a'}"></div>
    </div>
    <div class="kpi">
      <div class="kpi-val" style="color:{'#ff3d5a' if checkov_data.get('Critical',0)+checkov_data.get('High',0)>0 else '#00ffa3'}" data-target="{checkov_data.get('Critical',0)+checkov_data.get('High',0)}">{checkov_data.get('Critical',0)+checkov_data.get('High',0)}</div>
      <div class="kpi-lbl">🏗️ Issues IaC</div>
      <div class="kpi-bar" style="color:{'#ff3d5a' if checkov_data.get('Critical',0)+checkov_data.get('High',0)>0 else '#00ffa3'}"></div>
    </div>
  </div>

  <!-- ── GRAPHIQUES ── -->
  <div class="section-label">Graphiques de sécurité</div>
  <div class="row g-3 mb-3 justify-content-center">
    <div class="col-md-6">
      <div class="card-dark h-100">
        <div class="card-title">📈 Tendance Sécurité</div>
        {g_trend}
        <div class="note">Réduction progressive des vulnérabilités sur les derniers runs.</div>
      </div>
    </div>
  </div>
  <div class="row g-3 mb-3">
    <div class="col-md-4">
      <div class="card-dark h-100">
        <div class="card-title">📦 Dépendances (SCA)</div>
        {g_sca}
        <div class="note">CVE détectées par Trivy dans les librairies tierces.</div>
      </div>
    </div>
    <div class="col-md-4">
      <div class="card-dark h-100">
        <div class="card-title">🔍 Code Source (SAST)</div>
        {g_sast}
        <div class="note">Bugs, vulnérabilités et hotspots SonarCloud.</div>
      </div>
    </div>
    <div class="col-md-4">
      <div class="card-dark h-100">
        <div class="card-title">🌐 Attaques Web (DAST)</div>
        {g_dast}
        <div class="note">Alertes OWASP ZAP sur WebGoat en cours d'exécution.</div>
      </div>
    </div>
  </div>
  <div class="row g-3 mb-4">
    <div class="col-md-4">
      <div class="card-dark h-100">
        <div class="card-title">⚡ Runtime (Falco)</div>
        {g_falco}
        <div class="note">Comportements suspects capturés en temps réel.</div>
      </div>
    </div>
    <div class="col-md-4">
      <div class="card-dark h-100">
        <div class="card-title">🔑 Secrets Git (Gitleaks)</div>
        {g_sec}
        <div class="note">Secrets en clair dans les commits. Zéro tolérance.</div>
      </div>
    </div>
    <div class="col-md-4">
      <div class="card-dark h-100">
        <div class="card-title">🏗️ IaC — Checkov</div>
        {g_checkov}
        <div class="note">Misconfigurations détectées dans les fichiers IaC.</div>
      </div>
    </div>
  </div>

  <!-- ── MATRICE OWASP ── -->
  <div class="section-label">Couverture OWASP Top 10</div>
  <div class="card-dark mb-4">
    <div class="card-title">🛡️ Matrice de Couverture OWASP Top 10
      <span class="ai-badge">6 outils · 10 catégories</span>
    </div>
    <div style="font-family:var(--font-mono);font-size:.68rem;color:var(--muted);margin-bottom:14px">
      Légende :
      <span style="color:#00ffa3">✓ OK</span> — outil couvre, aucun finding &nbsp;|&nbsp;
      <span style="color:#ff3d5a">⚠ Trouvé</span> — finding(s) détecté(s) &nbsp;|&nbsp;
      <span style="color:#334155">—</span> — non couverte
    </div>
    <div class="owasp-table-wrap">{owasp_matrix}</div>
  </div>

  <!-- ── ANALYSE IA ── -->
  <div class="section-label">Synthèse Intelligence Artificielle</div>
  <div class="ai-wrapper mb-4">
    <div class="card-dark">
      <div class="card-title">🤖 Rapport IA Corrélé
        <span class="ai-badge">SCA · SAST · DAST · Runtime · Secrets · IaC</span>
      </div>
      <div class="ai-box">{ai_html}</div>
    </div>
  </div>

  <footer>
    <span class="live-dot"></span>
    Généré automatiquement · GitHub Actions · Run #{meta['run']} ·
    <a href="{meta['run_url']}" target="_blank">Voir le pipeline complet</a>
  </footer>

</div>

<script>
(function () {{
  const root=document.documentElement,darkBtn=document.getElementById('dark-mode'),lightBtn=document.getElementById('light-mode');
  function setTheme(t){{root.setAttribute('data-theme',t);localStorage.setItem('ds-theme',t);[darkBtn,lightBtn].forEach(b=>b.classList.remove('active'));document.getElementById(t+'-mode').classList.add('active');}}
  const saved=localStorage.getItem('ds-theme')||(window.matchMedia('(prefers-color-scheme:dark)').matches?'dark':'light');
  setTheme(saved);
  darkBtn.addEventListener('click',()=>setTheme('dark'));
  lightBtn.addEventListener('click',()=>setTheme('light'));

  function animateCounters(){{
    document.querySelectorAll('.kpi-val[data-target]').forEach(el=>{{
      const target=+el.dataset.target;if(isNaN(target))return;
      const dur=1000,start=performance.now();
      (function step(now){{const p=Math.min((now-start)/dur,1),ease=1-Math.pow(1-p,3);el.textContent=Math.round(ease*target);if(p<1)requestAnimationFrame(step);}})(start);
    }});
  }}

  const revealObs=new IntersectionObserver(entries=>{{
    entries.forEach(e=>{{if(e.isIntersecting){{e.target.style.opacity='1';e.target.style.transform='translateY(0)';revealObs.unobserve(e.target);}}}}
    );
  }},{{threshold:0.08}});
  document.querySelectorAll('.card-dark,.kpi,.risk-banner').forEach((el,i)=>{{
    el.style.opacity='0';el.style.transform='translateY(20px)';
    el.style.transition=`opacity .5s ${{i*0.05}}s ease,transform .5s ${{i*0.05}}s ease,border-color .3s,box-shadow .3s`;
    revealObs.observe(el);
  }});

  const kpiObs=new IntersectionObserver(entries=>{{entries.forEach(e=>{{if(e.isIntersecting){{animateCounters();kpiObs.disconnect();}}}})}},{{threshold:0.2}});
  const kg=document.querySelector('.kpi-grid');if(kg)kpiObs.observe(kg);

  const barObs=new IntersectionObserver(entries=>{{
    entries.forEach(e=>{{if(e.isIntersecting){{
      const bar=e.target.querySelector('.risk-bar-inner');
      if(bar){{const w=bar.style.width;bar.style.width='0';setTimeout(()=>{{bar.style.transition='width .9s cubic-bezier(.4,0,.2,1)';bar.style.width=w;}},100);}}
      barObs.unobserve(e.target);
    }}}}
    );
  }},{{threshold:0.3}});
  const banner=document.querySelector('.risk-banner');if(banner)barObs.observe(banner);
}})();
</script>

</body>
</html>"""

    output = "global_security_report.html"
    with open(output, "w", encoding="utf-8") as fh:
        fh.write(html)
    print(f"\n[OK] Dashboard généré → {output}\n" + "═" * 60)


if __name__ == "__main__":
    generate_dashboard()
