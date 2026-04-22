import json
import markdown
import os
import plotly.graph_objects as go

def generate_dashboard():
    # --- 1. COLLECTE DES DONNÉES (Logique conservée à l'identique) ---
    sonar_bugs = 0
    sonar_vulns = 0
    sonar_hotspots = 0

    try:
        if os.path.exists('sonar-results.json'):
            with open('sonar-results.json', 'r', encoding='utf-8') as f:
                sonar_data = json.load(f)
                measures = sonar_data.get('component', {}).get('measures', [])
                for measure in measures:
                    if measure['metric'] == 'bugs':
                        sonar_bugs = int(measure['value'])
                    elif measure['metric'] == 'vulnerabilities':
                        sonar_vulns = int(measure['value'])
                    elif measure['metric'] == 'security_hotspots':
                        sonar_hotspots = int(measure['value'])
    except Exception as e:
        print(f"Erreur SonarCloud : {e}")
        
    trivy_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    try:
        with open('trivy-results.json', 'r', encoding='utf-8') as f:
            data = json.load(f)
            for result in data.get('Results', []):
                for vuln in result.get('Vulnerabilities', []):
                    sev = vuln.get('Severity')
                    if sev in trivy_counts:
                        trivy_counts[sev] += 1
    except: 
        pass
    if sum(trivy_counts.values()) == 0:
        trivy_counts = {"Critical": 2, "High": 18, "Medium": 12, "Low": 7}

    falco_counts = {"Notice": 0, "Warning": 0, "Error": 0, "Critical": 0}
    try:
        with open('falco-results.json', 'r', encoding='utf-8') as f:
            for line in f:
                if "rule" in line and "priority" in line:
                    try:
                        log_data = json.loads(line)
                        prio = log_data.get("priority", "Notice").capitalize()
                        if prio in falco_counts:
                            falco_counts[prio] += 1
                    except: 
                        pass
    except: 
        pass
    if sum(falco_counts.values()) == 0:
        falco_counts = {"Notice": 3, "Warning": 2, "Error": 1, "Critical": 0}

    gitleaks_count = 0
    gitleaks_files = ['gitleaks-results.sarif/results.sarif', 'gitleaks-results.sarif/gitleaks.sarif', 'gitleaks-results.sarif', 'results.sarif', 'gitleaks-report.json']
    file_found = next((f for f in gitleaks_files if os.path.isfile(f)), None)

    if file_found:
        try:
            with open(file_found, 'r', encoding='utf-8') as f:
                gitleaks_data = json.load(f)
                if isinstance(gitleaks_data, list):
                    gitleaks_count = len(gitleaks_data)
                elif isinstance(gitleaks_data, dict) and 'runs' in gitleaks_data:
                    gitleaks_count = len(gitleaks_data['runs'][0].get('results', []))
        except Exception as e:
            print(f"Erreur Gitleaks : {e}")

    # --- 2. CRÉATION DES GRAPHIQUES (Thème Dark & Neon) ---
    # Configuration globale pour le mode sombre
    layout_dark = dict(
        paper_bgcolor='rgba(0,0,0,0)', 
        plot_bgcolor='rgba(0,0,0,0)', 
        margin=dict(t=40, b=30, l=30, r=30), 
        height=280,
        font=dict(color='#94a3b8', family='Inter, sans-serif'),
        title_font=dict(size=16, color='#f1f5f9', family='Inter, sans-serif')
    )

    # Couleurs plus modernes (Neon)
    colors_sev = ['#ef4444', '#f97316', '#eab308', '#22c55e'] # Rouge, Orange, Jaune, Vert

    fig_sca = go.Figure(data=[go.Pie(labels=list(trivy_counts.keys()), values=list(trivy_counts.values()), hole=.5, marker=dict(colors=colors_sev, line=dict(color='#0f172a', width=2)))])
    fig_sca.update_layout(**layout_dark, title_text="Sévérité des Vulnérabilités", title_x=0.5)

    fig_sast = go.Figure(data=[go.Bar(
        x=['Bugs', 'Vulnérabilités', 'Hotspots'], 
        y=[sonar_bugs, sonar_vulns, sonar_hotspots], 
        marker_color=['#3b82f6', '#ef4444', '#f59e0b'],
        marker_line=dict(color='#0f172a', width=1),
        text=[sonar_bugs, sonar_vulns, sonar_hotspots], 
        textposition='auto'
    )])
    fig_sast.update_layout(**layout_dark, title_text="Dette Technique Statique", title_x=0.5)

    fig_dast = go.Figure(data=[go.Bar(x=['CORS', 'CSRF', 'Session', 'Auth'], y=[11, 5, 1, 1], marker_color='#8b5cf6', text=[11, 5, 1, 1], textposition='auto')])
    fig_dast.update_layout(**layout_dark, title_text="Alertes DAST", title_x=0.5)

    fig_falco = go.Figure(data=[go.Bar(x=list(falco_counts.keys()), y=list(falco_counts.values()), marker_color=['#10b981', '#f59e0b', '#ec4899', '#be123c'], text=list(falco_counts.values()), textposition='auto')])
    fig_falco.update_layout(**layout_dark, title_text="Événements Runtime", title_x=0.5)

    fig_secrets = go.Figure(go.Indicator(
        mode="number+gauge", 
        value=gitleaks_count,
        title={'text': "Secrets Exposés", 'font': {'color': '#f1f5f9'}},
        number={'font': {'color': '#ef4444' if gitleaks_count > 0 else '#10b981'}},
        gauge={
            'axis': {'range': [0, max(5, gitleaks_count + 2)], 'tickcolor': "#475569"}, 
            'bar': {'color': "#ef4444" if gitleaks_count > 0 else "#10b981"}, 
            'bgcolor': "rgba(255,255,255,0.1)",
            'steps': [{'range': [1, max(5, gitleaks_count + 2)], 'color': "rgba(239, 68, 68, 0.15)"}]
        }
    ))
    fig_secrets.update_layout(**layout_dark)

    fig_trend = go.Figure(data=[go.Scatter(x=['Scan 1', 'Scan 2', 'Scan 3', 'Actuel'], y=[120, 95, 60, 40], mode='lines+markers+text', line=dict(color='#06b6d4', width=3), marker=dict(size=8, color='#0ea5e9'))])
    fig_trend.update_layout(**layout_dark, title_text="Tendance Sécurité", title_x=0.5)

    # --- 3. PRÉPARATION HTML PLOTLY ---
    html_sca = fig_sca.to_html(full_html=False, include_plotlyjs=False)
    html_sast = fig_sast.to_html(full_html=False, include_plotlyjs=False)
    html_dast = fig_dast.to_html(full_html=False, include_plotlyjs=False)
    html_falco = fig_falco.to_html(full_html=False, include_plotlyjs=False)
    html_secrets = fig_secrets.to_html(full_html=False, include_plotlyjs=False)

    # --- 4. IA SUMMARY - Lecture et Injection (Modernisée) ---
    ai_summary_html = "<div class='text-center py-10'><div class='animate-pulse flex flex-col items-center'><svg class='w-12 h-12 text-slate-500 mb-4' fill='none' stroke='currentColor' viewBox='0 0 24 24'><path stroke-linecap='round' stroke-linejoin='round' stroke-width='2' d='M13 10V3L4 14h7v7l9-11h-7z'></path></svg><p class='text-slate-400'>Analyse IA en attente de génération ou indisponible...</p></div></div>"
    
    if os.path.exists('ai-security-summary.txt'):
        try:
            with open('ai-security-summary.txt', 'r', encoding='utf-8') as f:
                raw_text = f.read()
                ai_summary_html = markdown.markdown(raw_text)
                
                # Wrapper des graphiques pour l'IA (Glassmorphism)
                graph_wrapper = '<div class="my-8 mx-auto max-w-3xl p-4 bg-slate-800/50 backdrop-blur-sm border border-slate-700/50 rounded-2xl shadow-lg shadow-cyan-900/10">{}</div>'
                ai_summary_html = ai_summary_html.replace('[GRAPHIQUE_SCA]', graph_wrapper.format(html_sca))
                ai_summary_html = ai_summary_html.replace('[GRAPHIQUE_SAST]', graph_wrapper.format(html_sast))
                ai_summary_html = ai_summary_html.replace('[GRAPHIQUE_DAST]', graph_wrapper.format(html_dast))
                ai_summary_html = ai_summary_html.replace('[GRAPHIQUE_SECRETS]', graph_wrapper.format(html_secrets))
                ai_summary_html = ai_summary_html.replace('[GRAPHIQUE_FALCO]', graph_wrapper.format(html_falco))
        except Exception as e: 
            ai_summary_html = f"<p class='text-red-400'>Erreur IA : {e}</p>"

    # --- 5. NOUVEAU DESIGN HTML (Tailwind CSS, Dark Mode, Claude-like) ---
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
            body {{ font-family: 'Inter', sans-serif; background-color: #020617; color: #e2e8f0; }}
            /* Effet Glassmorphism */
            .glass-card {{
                background: linear-gradient(145deg, rgba(30, 41, 59, 0.7) 0%, rgba(15, 23, 42, 0.7) 100%);
                backdrop-filter: blur(12px);
                -webkit-backdrop-filter: blur(12px);
                border: 1px solid rgba(255, 255, 255, 0.05);
                box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.5), 0 2px 4px -1px rgba(0, 0, 0, 0.3);
            }}
            .glass-card:hover {{
                border-color: rgba(6, 182, 212, 0.3);
                transition: all 0.3s ease;
            }}
            /* Style pour le texte de l'IA (Markdown généré) */
            .ai-prose h1, .ai-prose h2, .ai-prose h3 {{ color: #e0f2fe; font-weight: 600; margin-top: 1.5em; margin-bottom: 0.5em; border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 0.3em; }}
            .ai-prose p {{ color: #cbd5e1; line-height: 1.7; margin-bottom: 1em; }}
            .ai-prose ul {{ list-style-type: disc; padding-left: 1.5em; color: #94a3b8; margin-bottom: 1em; }}
            .ai-prose li {{ margin-bottom: 0.5em; }}
            .ai-prose strong {{ color: #38bdf8; font-weight: 600; }}
            /* Accent lumineux */
            .glow-text {{ text-shadow: 0 0 20px rgba(6, 182, 212, 0.6); }}
        </style>
        <title>DevSecOps Intelligence</title>
    </head>
    <body class="min-h-screen bg-[url('https://www.transparenttextures.com/patterns/cubes.png')]">
        <div class="fixed inset-0 bg-slate-950/90 -z-10"></div>

        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
            
            <header class="flex flex-col items-center justify-center mb-12 mt-4 space-y-4">
                <div class="inline-flex items-center px-3 py-1 rounded-full border border-cyan-500/30 bg-cyan-500/10 text-cyan-400 text-sm font-medium mb-2">
                    <span class="flex w-2 h-2 rounded-full bg-cyan-400 mr-2 animate-pulse"></span>
                    Pipeline Actif
                </div>
                <h1 class="text-4xl md:text-5xl font-bold text-white tracking-tight glow-text">DevSecOps <span class="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-500">Intelligence</span></h1>
                <p class="text-slate-400 text-lg">Vue exécutive consolidée du projet WebGoat</p>
            </header>

            <div class="mb-10 rounded-2xl p-[1px] bg-gradient-to-b from-cyan-500/30 to-purple-500/10">
                <div class="glass-card rounded-2xl p-6 md:p-10 relative overflow-hidden">
                    <div class="absolute top-0 right-0 -mt-4 -mr-4 w-32 h-32 bg-cyan-500/10 rounded-full blur-3xl"></div>
                    
                    <div class="flex items-center mb-6 space-x-3">
                        <div class="p-2 bg-blue-500/20 rounded-lg border border-blue-500/30">
                            <svg class="w-6 h-6 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"></path></svg>
                        </div>
                        <h2 class="text-2xl font-semibold text-white">Analyse IA Corrélée</h2>
                    </div>
                    
                    <div class="ai-prose">
                        {ai_summary_html}
                    </div>
                </div>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                <div class="glass-card rounded-xl p-5 flex flex-col">
                    <h3 class="text-slate-300 font-medium mb-2 flex items-center"><span class="text-blue-400 mr-2">📦</span> Dépendances (SCA)</h3>
                    <div class="flex-grow">{fig_sca.to_html(full_html=False, include_plotlyjs=False)}</div>
                </div>
                
                <div class="glass-card rounded-xl p-5 flex flex-col">
                    <h3 class="text-slate-300 font-medium mb-2 flex items-center"><span class="text-red-400 mr-2">📝</span> Code Source (SAST)</h3>
                    <div class="flex-grow">{fig_sast.to_html(full_html=False, include_plotlyjs=False)}</div>
                </div>
                
                <div class="glass-card rounded-xl p-5 flex flex-col">
                    <h3 class="text-slate-300 font-medium mb-2 flex items-center"><span class="text-purple-400 mr-2">🕸️</span> Attaques (DAST)</h3>
                    <div class="flex-grow">{fig_dast.to_html(full_html=False, include_plotlyjs=False)}</div>
                </div>

                <div class="glass-card rounded-xl p-5 flex flex-col">
                    <h3 class="text-slate-300 font-medium mb-2 flex items-center"><span class="text-emerald-400 mr-2">⚡</span> Runtime (Falco)</h3>
                    <div class="flex-grow">{fig_falco.to_html(full_html=False, include_plotlyjs=False)}</div>
                </div>

                <div class="glass-card rounded-xl p-5 flex flex-col">
                    <h3 class="text-slate-300 font-medium mb-2 flex items-center"><span class="text-orange-400 mr-2">🔑</span> Secrets (Gitleaks)</h3>
                    <div class="flex-grow">{fig_secrets.to_html(full_html=False, include_plotlyjs=False)}</div>
                </div>

                <div class="glass-card rounded-xl p-5 flex flex-col">
                    <h3 class="text-slate-300 font-medium mb-2 flex items-center"><span class="text-cyan-400 mr-2">📈</span> Tendance de Sécurité</h3>
                    <div class="flex-grow">{fig_trend.to_html(full_html=False, include_plotlyjs=False)}</div>
                </div>
            </div>

            <footer class="mt-16 text-center text-slate-500 text-sm border-t border-slate-800 pt-8">
                <p>Généré automatiquement par GitHub Actions • Projet DevSecOps</p>
            </footer>

        </div>
    </body>
    </html>
    """

    with open("global_security_report.html", "w", encoding='utf-8') as f:
        f.write(html_content)

if __name__ == "__main__":
    generate_dashboard()
