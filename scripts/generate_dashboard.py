# generate_dashboard.py
# Version corrigée finale :
# ✅ Plus de SyntaxError
# ✅ Dark / Light mode OK
# ✅ Résumé IA visible
# ✅ Compatible GitHub Actions

import json
import os
import re
import sys
from datetime import datetime, timezone

import plotly.graph_objects as go


# ==========================================================
# PARSERS
# ==========================================================

def parse_json_file(path, default):
    if not os.path.isfile(path):
        return default
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except:
        return default


def parse_trivy(path="trivy-results.json"):
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    data = parse_json_file(path, {})
    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            sev = vuln.get("Severity", "").title()
            if sev in counts:
                counts[sev] += 1
    return counts


def parse_sonar(path="sonar-results.json"):
    default = {"bugs": 0, "vulnerabilities": 0, "security_hotspots": 0}
    data = parse_json_file(path, {})
    for m in data.get("component", {}).get("measures", []):
        metric = m.get("metric")
        if metric in default:
            default[metric] = int(m.get("value", 0))
    return default


def parse_gitleaks(path="gitleaks-report.json"):
    data = parse_json_file(path, [])
    return len(data) if isinstance(data, list) else 0


def parse_ai_summary(path="ai-security-summary.txt"):
    if not os.path.isfile(path):
        return "# Analyse IA\nAucun résumé IA disponible."
    with open(path, encoding="utf-8") as f:
        txt = f.read().strip()
        return txt if txt else "# Analyse IA\nRésumé vide."


# ==========================================================
# MARKDOWN -> HTML
# ==========================================================

def md_to_html(text):
    lines = text.split("\n")   # ✅ CORRECTION IMPORTANTE
    out = []
    in_ul = False

    for line in lines:
        line = line.strip()

        if line.startswith("### "):
            if in_ul:
                out.append("</ul>")
                in_ul = False
            out.append(f"<h3>{line[4:]}</h3>")

        elif line.startswith("## "):
            if in_ul:
                out.append("</ul>")
                in_ul = False
            out.append(f"<h2>{line[3:]}</h2>")

        elif line.startswith("# "):
            if in_ul:
                out.append("</ul>")
                in_ul = False
            out.append(f"<h1>{line[2:]}</h1>")

        elif line.startswith("- "):
            if not in_ul:
                out.append("<ul>")
                in_ul = True

            item = line[2:]
            item = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", item)
            item = re.sub(r"\*(.+?)\*", r"<em>\1</em>", item)

            out.append(f"<li>{item}</li>")

        elif line == "":
            if in_ul:
                out.append("</ul>")
                in_ul = False

        else:
            if in_ul:
                out.append("</ul>")
                in_ul = False

            line = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", line)
            line = re.sub(r"\*(.+?)\*", r"<em>\1</em>", line)

            out.append(f"<p>{line}</p>")

    if in_ul:
        out.append("</ul>")

    return "\n".join(out)


# ==========================================================
# FIGURES
# ==========================================================

def fig_trivy(data):
    fig = go.Figure(
        data=[go.Pie(
            labels=list(data.keys()),
            values=list(data.values()),
            hole=0.45
        )]
    )
    fig.update_layout(template="plotly_dark", height=320)
    return fig.to_html(full_html=False, include_plotlyjs=False)


def fig_sonar(data):
    labels = ["Bugs", "Vuln", "Hotspots"]
    values = [
        data["bugs"],
        data["vulnerabilities"],
        data["security_hotspots"]
    ]

    fig = go.Figure(data=[go.Bar(x=labels, y=values)])
    fig.update_layout(template="plotly_dark", height=320)
    return fig.to_html(full_html=False, include_plotlyjs=False)


def fig_gitleaks(count):
    fig = go.Figure(go.Indicator(
        mode="number",
        value=count
    ))
    fig.update_layout(template="plotly_dark", height=320)
    return fig.to_html(full_html=False, include_plotlyjs=False)


# ==========================================================
# DASHBOARD
# ==========================================================

def generate_dashboard():

    trivy = parse_trivy()
    sonar = parse_sonar()
    gitleaks = parse_gitleaks()
    ai_text = parse_ai_summary()

    ai_html = md_to_html(ai_text)

    total_cve = sum(trivy.values())

    meta = {
        "sha": os.getenv("GITHUB_SHA", "local")[:8],
        "run": os.getenv("GITHUB_RUN_NUMBER", "0"),
        "branch": os.getenv("GITHUB_REF_NAME", "main"),
        "actor": os.getenv("GITHUB_ACTOR", "local"),
        "time": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    }

    # ======================================================
    # THEME BLOCK (séparé => évite SyntaxError)
    # ======================================================

    theme_block = """
<div id="theme-toggle">
<button id="dark-mode" class="theme-btn active">🌙</button>
<button id="light-mode" class="theme-btn">☀️</button>
</div>

<script>
document.addEventListener("DOMContentLoaded", function(){

const darkBtn = document.getElementById("dark-mode");
const lightBtn = document.getElementById("light-mode");
const root = document.documentElement;

const saved = localStorage.getItem("theme") || "dark";
setTheme(saved);

darkBtn.onclick = () => setTheme("dark");
lightBtn.onclick = () => setTheme("light");

function setTheme(mode){
    root.setAttribute("data-theme", mode);
    localStorage.setItem("theme", mode);

    darkBtn.classList.remove("active");
    lightBtn.classList.remove("active");

    if(mode === "dark"){
        darkBtn.classList.add("active");
    } else {
        lightBtn.classList.add("active");
    }
}

});
</script>
"""

    # ======================================================
    # HTML
    # ======================================================

    html = f"""
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">

<title>Security Dashboard</title>

<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
<script src="https://cdn.plot.ly/plotly-latest.min.js"></script>

<style>

:root {{
--bg:#0a0f1e;
--card:#111827;
--text:#f8fafc;
--muted:#94a3b8;
--accent:#38bdf8;
}}

[data-theme="light"] {{
--bg:#f8fafc;
--card:#ffffff;
--text:#0f172a;
--muted:#475569;
--accent:#2563eb;
}}

body {{
background:var(--bg);
color:var(--text);
font-family:Arial, sans-serif;
padding:30px;
transition:0.3s;
}}

.card {{
background:var(--card);
border:none;
border-radius:16px;
padding:20px;
margin-bottom:20px;
}}

h1,h2,h3 {{
color:var(--accent);
}}

#theme-toggle {{
position:fixed;
top:20px;
right:20px;
z-index:9999;
display:flex;
gap:10px;
}}

.theme-btn {{
border:none;
padding:10px 14px;
border-radius:12px;
cursor:pointer;
}}

.theme-btn.active {{
outline:2px solid var(--accent);
}}

</style>

{theme_block}

</head>
<body>

<h1>🛡️ DevSecOps Dashboard</h1>

<p>
Branch: {meta["branch"]} |
Run: #{meta["run"]} |
Commit: {meta["sha"]} |
By: {meta["actor"]} |
{meta["time"]}
</p>

<div class="row">

<div class="col-md-4">
<div class="card">
<h3>📦 CVE Total</h3>
<h2>{total_cve}</h2>
</div>
</div>

<div class="col-md-4">
<div class="card">
<h3>🔑 Secrets</h3>
<h2>{gitleaks}</h2>
</div>
</div>

<div class="col-md-4">
<div class="card">
<h3>🔍 SAST Issues</h3>
<h2>{sonar["bugs"] + sonar["vulnerabilities"]}</h2>
</div>
</div>

</div>

<div class="row">

<div class="col-md-4">
<div class="card">
<h3>Trivy</h3>
{fig_trivy(trivy)}
</div>
</div>

<div class="col-md-4">
<div class="card">
<h3>Sonar</h3>
{fig_sonar(sonar)}
</div>
</div>

<div class="col-md-4">
<div class="card">
<h3>Gitleaks</h3>
{fig_gitleaks(gitleaks)}
</div>
</div>

</div>

<div class="card">
<h2>🤖 Synthèse IA</h2>
{ai_html}
</div>

</body>
</html>
"""

    with open("global_security_report.html", "w", encoding="utf-8") as f:
        f.write(html)

    print("[OK] global_security_report.html généré")


if __name__ == "__main__":
    generate_dashboard()
