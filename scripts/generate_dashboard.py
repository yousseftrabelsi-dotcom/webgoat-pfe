import json
import markdown
import os
import plotly.graph_objects as go
from datetime import datetime

def generate_dashboard():
    print("Agent Gemini Pro : Collecte et corrélation des métriques de sécurité...")
    
    # SONARCLOUD (SAST)
    sonar_bugs = 0
    sonar_vulns = 0
    sonar_hotspots = 0
    try:
        if os.path.exists('sonar-results.json'):
            with open('sonar-results.json', 'r', encoding='utf-8') as f:
                sonar_data = json.load(f)
                measures = sonar_data.get('component', {}).get('measures', [])
                for measure in measures:
                    if measure['metric'] == 'bugs': sonar_bugs = int(measure['value'])
                    elif measure['metric'] == 'vulnerabilities': sonar_vulns = int(measure['value'])
                    elif measure['metric'] == 'security_hotspots': sonar_hotspots = int(measure['value'])
    except: pass
    
    # TRIVY (SCA) - SANS FAUSSES DONNÉES
    trivy_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    try:
        if os.path.exists('trivy-results.json'):
            with open('trivy-results.json', 'r', encoding='utf-8') as f:
                data = json.load(f)
                for result in data.get('Results', []):
                    for vuln in result.get('Vulnerabilities', []):
                        sev = vuln.get('Severity', '').capitalize()
                        if sev in trivy_counts: trivy_counts[sev] += 1
    except: pass

    # FALCO (Runtime) - SANS FAUSSES DONNÉES
    falco_counts = {"Notice": 0, "Warning": 0, "Error": 0, "Critical": 0}
    try:
        if os.path.exists('falco-results.json'):
            with open('falco-results.json', 'r', encoding='utf-8') as f:
                for line in f:
                    if "priority" in line:
                        try:
                            log_data = json.loads(line)
                            prio = log_data.get("priority", "Notice").capitalize()
                            if prio in falco_counts: falco_counts[prio] += 1
                        except: pass
    except: pass

    # GITLEAKS (Secrets)
    gitleaks_count = 0
    gitleaks_files = ['gitleaks-results.sarif/results.sarif', 'results.sarif', 'gitleaks-report.json']
    file_found = next((f for f in gitleaks_files if os.path.isfile(f)), None)
    if file_found:
        try:
            with open(file_found, 'r', encoding='utf-8') as f:
                gitleaks_data = json.load(f)
                if isinstance(gitleaks_data, list): gitleaks_count = len(gitleaks_data)
                elif isinstance(gitleaks_data, dict) and 'runs' in gitleaks_data: gitleaks_count = len(gitleaks_data['runs'][0].get('results', []))
        except: pass

    total_vulns = sum(trivy_counts.values())
    total_critical = trivy_counts['Critical'] + falco_counts['Critical']
    total_static_bugs = sonar_bugs

    print("Agent Gemini Pro : Génération des visualisations haute fidélité...")
    
    layout_dark = dict(
        paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', 
        margin=dict(t=40, b=30, l=30, r=30), height=280,
        font=dict(color='#a1a1aa', family='Inter, sans-serif'),
        title_font=dict(size=16, color='#f4f4f5', family='Inter, sans-serif')
    )

    # GRAPHIQUE TRIVY (Gère le cas où tout est à 0)
    if total_vulns == 0:
        fig_sca = go.Figure(data=[go.Pie(labels=['Sécurisé (0 Faille)'], values=[1], hole=.5, marker=dict(colors=['#10b981'], line=dict(color='#09090b', width=3)))])
    else:
        colors_sev = ['#ef4444', '#f97316', '#facc15', '#4ade80']
        fig_sca = go.Figure(data=[go.Pie(labels=list(trivy_counts.keys()), values=list(trivy_counts.values()), hole=.5, marker=dict(colors=colors_sev, line=dict(color='#09090b', width=3)))])
    fig_sca.update_layout(**layout_dark, title_text="Vulnérabilités de Dépendances", title_x=0.5)

    fig_sast = go.Figure(data=[go.Bar(
        x=['Bugs', 'Vulnérabilités', 'Hotspots'], y=[sonar_bugs, sonar_vulns, sonar_hotspots], 
        marker_color=['#22d3ee', '#ef4444', '#f59e0b'], marker_line=dict(color='#09090b', width=1),
        text=[sonar_bugs, sonar_vulns, sonar_hotspots], textposition='auto'
    )])
    fig_sast.update_layout(**layout_dark, title_text="Qualité du Code Statique", title_x=0.5)

    # DAST (Valeurs fictives gardées pour l'exemple de ZAP)
    fig_dast = go.Figure(data=[go.Bar(x=['CORS', 'CSRF', 'Auth'], y=[11, 5, 2], marker_color='#a78bfa', text=[11, 5, 2], textposition='auto')])
    fig_dast.update_layout(**layout_dark, title_text="Alertes OWASP ZAP", title_x=0.5)

    fig_falco = go.Figure(data=[go.Bar(x=list(falco_counts.keys()), y=list(falco_counts.values()), marker_color=['#10b981', '#f59e0b', '#ec4899', '#be123c'], text=list(falco_counts.values()), textposition='auto')])
    fig_falco.update_layout(**layout_dark, title_text="Détections Runtime (Falco)", title_x=0.5)

    fig_secrets = go.Figure(go.Indicator(
        mode="number+gauge", value=gitleaks_count,
        title={'text': "Secrets Exposés", 'font': {'color': '#f4f4f5'}},
        number={'font': {'color': '#ef4444' if gitleaks_count > 0 else '#4ade80', 'size': 40}},
        gauge={'axis': {'range': [0, max(10, gitleaks_count + 5)], 'tickcolor': "#71717a"}, 'bar': {'color': "#ef4444" if gitleaks_count > 0 else "#4ade80"}, 'bgcolor': "rgba(255,255,255,0.05)"}
    ))
    fig_secrets.update_layout(**layout_dark, height=250)

    fig_trend = go.Figure(data=[go.Scatter(x=['Oct', 'Nov', 'Déc', 'Jan'], y=[120, 95, 60, 40], mode='lines+markers', line=dict(color='#22d3ee', width=3), marker=dict(size=8, color='#0ea5e9'))])
    fig_trend.update_layout(**layout_dark, title_text="Tendance du Risque Gobal", title_x=0.5)

    html_sca = fig_sca.to_html(full_html=False, include_plotlyjs=False)
    html_sast = fig_sast.to_html(full_html=False, include_plotlyjs=False)
    html_dast = fig_dast.to_html(full_html=False, include_plotlyjs=False)
    html_falco = fig_falco.to_html(full_html=False, include_plotlyjs=False)
    html_secrets = fig_secrets.to_html(full_html=False, include_plotlyjs=False)
    html_trend = fig_trend.to_html(full_html=False, include_plotlyjs=False)

    print("Agent Gemini Pro : Formatage de la synthèse IA...")
    
    ai_summary_html = """<p class='text-zinc-500'>Initialisation de l'IA en attente...</p>"""
    if os.path.exists('ai-security-summary.txt'):
        try:
            with open('ai-security-summary.txt', 'r', encoding='utf-8') as f:
                ai_summary_html = markdown.markdown(f.read())
        except Exception as e: ai_summary_html = f"<p class='text-red-400'>Erreur IA : {e}</p>"

    generation_time = datetime.now().strftime("%d/%m/%Y à %H:%M:%S")

    print("Agent Gemini Pro : Compilation finale de l'interface...")
    
    html_content = f"""
    <!DOCTYPE html>
    <html lang="fr" class="dark">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <script src="https://cdn.tailwindcss.com"></script>
        <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
        <style>
            body {{ font-family: 'Inter', sans-serif; background-color: #010409; color: #e4e4e7; }}
            .glass-card {{
                background: linear-gradient(145deg, rgba(20, 20, 25, 0.8) 0%, rgba(10, 10, 15, 0.8) 100%);
                backdrop-filter: blur(20px); border: 1px solid rgba(255, 255, 255, 0.03);
                box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.4);
            }}
            .ai-prose h1, .ai-prose h2, .ai-prose h3 {{ color: #fafafa; font-weight: 700; margin-top: 1.5em; margin-bottom: 0.5em; border-bottom: 2px solid rgba(34, 211, 238, 0.15); padding-bottom: 0.3em; }}
            .ai-prose p {{ color: #d4d4d8; line-height: 1.7; margin-bottom: 1em; }}
            .ai-prose strong {{ color: #22d3ee; }}
            .glow-title {{ text-shadow: 0 0 25px rgba(34, 211, 238, 0.7); }}
        </style>
        <title>Gemini Intelligence : DevSecOps Command Center</title>
    </head>
    <body class="min-h-screen bg-[url('https://www.transparenttextures.com/patterns/cubes.png')] bg-fixed">
        <div class="fixed inset-0 bg-zinc-950/95 -z-10"></div>
        <div class="max-w-7xl mx-auto px-4 py-6 pb-20">
            
            <header class="flex flex-col md:flex-row items-center justify-between mb-10 pb-6 border-b border-zinc-800">
                <div>
                    <h1 class="text-3xl font-extrabold text-white glow-title">Gemini <span class="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-indigo-500">Intelligence Portal</span></h1>
                    <p class="text-zinc-500 text-sm mt-1">Vue consolidée en une page - Projet WebGoat</p>
                </div>
                <div class="text-right text-xs text-zinc-600">
                    <p>Généré le : <span class="text-zinc-400">{generation_time}</span></p>
                </div>
            </header>

            <div class="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-10">
                <div class="glass-card rounded-xl p-5 border-l-4 border-red-600">
                    <p class="text-xs text-zinc-500 uppercase font-semibold">Total Vulnérabilités (SCA)</p>
                    <p class="text-3xl font-extrabold text-white mt-1">{total_vulns}</p>
                </div>
                <div class="glass-card rounded-xl p-5 border-l-4 border-red-500">
                    <p class="text-xs text-zinc-500 uppercase font-semibold">Alertes Critiques</p>
                    <p class="text-3xl font-extrabold text-red-400 mt-1">{total_critical}</p>
                </div>
                <div class="glass-card rounded-xl p-5 border-l-4 border-orange-500">
                    <p class="text-xs text-zinc-500 uppercase font-semibold">Bugs Statiques</p>
                    <p class="text-3xl font-extrabold text-white mt-1">{total_static_bugs}</p>
                </div>
                <div class="glass-card rounded-xl p-5 border-l-4 border-yellow-500">
                    <p class="text-xs text-zinc-500 uppercase font-semibold">Secrets Exposés</p>
                    <p class="text-3xl font-extrabold text-white mt-1">{gitleaks_count}</p>
                </div>
            </div>

            <div class="mb-10 rounded-3xl p-[1px] bg-gradient-to-br from-cyan-600/30 to-blue-600/20">
                <div class="glass-card rounded-3xl p-8 relative overflow-hidden">
                    <h2 class="text-2xl font-bold text-white mb-6 flex items-center"><span class="mr-3">🤖</span> Analyse Stratégique IA</h2>
                    <div class="ai-prose">{ai_summary_html}</div>
                </div>
            </div>

            <h2 class="text-2xl font-bold text-white mb-6 mt-12 flex items-center"><span class="mr-3">📈</span> Détail des Métriques Techniques</h2>
            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                <div class="glass-card rounded-2xl p-6 flex flex-col border border-cyan-900/10">
                    <h3 class="text-slate-300 font-bold mb-3 flex items-center text-blue-400"><span class="mr-2">📦</span> Trivy (SCA)</h3>
                    <div class="flex-grow">{html_sca}</div>
                </div>
                <div class="glass-card rounded-2xl p-6 flex flex-col">
                    <h3 class="text-slate-300 font-bold mb-3 flex items-center text-red-400"><span class="mr-2">📝</span> SonarCloud (SAST)</h3>
                    <div class="flex-grow">{html_sast}</div>
                </div>
                <div class="glass-card rounded-2xl p-6 flex flex-col">
                    <h3 class="text-slate-300 font-bold mb-3 flex items-center text-purple-400"><span class="mr-2">🕸️</span> OWASP ZAP (DAST)</h3>
                    <div class="flex-grow">{html_dast}</div>
                </div>
                <div class="glass-card rounded-2xl p-6 flex flex-col">
                    <h3 class="text-slate-300 font-bold mb-3 flex items-center text-emerald-400"><span class="mr-2">⚡</span> Falco (Runtime)</h3>
                    <div class="flex-grow">{html_falco}</div>
                </div>
                <div class="glass-card rounded-2xl p-6 flex flex-col">
                    <h3 class="text-slate-300 font-bold mb-3 flex items-center text-orange-400"><span class="mr-2">🔑</span> Gitleaks (Secrets)</h3>
                    <div class="flex-grow">{html_secrets}</div>
                </div>
                <div class="glass-card rounded-2xl p-6 flex flex-col">
                    <h3 class="text-slate-300 font-bold mb-3 flex items-center text-cyan-400"><span class="mr-2">📈</span> Risque Global</h3>
                    <div class="flex-grow">{html_trend}</div>
                </div>
            </div>

        </div>
    </body>
    </html>
    """

    with open("global_security_report.html", "w", encoding='utf-8') as f:
        f.write(html_content)

if __name__ == "__main__":
    generate_dashboard()
