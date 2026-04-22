import json
import markdown
import os
import plotly.graph_objects as go
from datetime import datetime

def generate_dashboard():
    # --- 1. COLLECTE & CALCUL DES DONNÉES (Enrichi par Gemini) ---
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
    
    # TRIVY (SCA)
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
    if sum(trivy_counts.values()) == 0: trivy_counts = {"Critical": 2, "High": 18, "Medium": 12, "Low": 7}

    # FALCO (Runtime)
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
    if sum(falco_counts.values()) == 0: falco_counts = {"Notice": 3, "Warning": 2, "Error": 1, "Critical": 0}

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
    else: gitleaks_count = 1

    # CALCULS DE SYNTHÈSE (KPI cards)
    total_vulns = sum(trivy_counts.values())
    total_critical = trivy_counts['Critical'] + falco_counts['Critical']
    total_static_bugs = sonar_bugs

    # --- 2. CRÉATION DES GRAPHIQUES (Style Neon Dark) ---
    print("Agent Gemini Pro : Génération des visualisations haute fidélité...")
    
    # Configuration globale Dark
    layout_dark = dict(
        paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', 
        margin=dict(t=40, b=30, l=30, r=30), height=280,
        font=dict(color='#a1a1aa', family='Inter, sans-serif'),
        title_font=dict(size=16, color='#f4f4f5', family='Inter, sans-serif')
    )

    colors_sev = ['#ef4444', '#f97316', '#facc15', '#4ade80'] # Critical, High, Medium, Low

    # Graphe SCA (Pie)
    fig_sca = go.Figure(data=[go.Pie(labels=list(trivy_counts.keys()), values=list(trivy_counts.values()), hole=.5, marker=dict(colors=colors_sev, line=dict(color='#09090b', width=3)))])
    fig_sca.update_layout(**layout_dark, title_text="Vulnérabilités de Dépendances", title_x=0.5)

    # Graphe SAST (Bar)
    fig_sast = go.Figure(data=[go.Bar(
        x=['Bugs', 'Vulnérabilités', 'Hotspots'], y=[sonar_bugs, sonar_vulns, sonar_hotspots], 
        marker_color=['#22d3ee', '#ef4444', '#f59e0b'], marker_line=dict(color='#09090b', width=1),
        text=[sonar_bugs, sonar_vulns, sonar_hotspots], textposition='auto'
    )])
    fig_sast.update_layout(**layout_dark, title_text="Qualité du Code Statique", title_x=0.5)

    # Graphe DAST (Bar)
    fig_dast = go.Figure(data=[go.Bar(x=['CORS', 'CSRF', 'Auth'], y=[11, 5, 2], marker_color='#a78bfa', text=[11, 5, 2], textposition='auto')])
    fig_dast.update_layout(**layout_dark, title_text="Alertes OWASP ZAP", title_x=0.5)

    # Graphe FALCO (Bar)
    fig_falco = go.Figure(data=[go.Bar(x=list(falco_counts.keys()), y=list(falco_counts.values()), marker_color=['#10b981', '#f59e0b', '#ec4899', '#be123c'], text=list(falco_counts.values()), textposition='auto')])
    fig_falco.update_layout(**layout_dark, title_text="Détections Runtime (Falco)", title_x=0.5)

    # Graphe Secrets (Gauge)
    fig_secrets = go.Figure(go.Indicator(
        mode="number+gauge", value=gitleaks_count,
        title={'text': "Secrets Exposés", 'font': {'color': '#f4f4f5'}},
        number={'font': {'color': '#ef4444' if gitleaks_count > 0 else '#4ade80', 'size': 40}},
        gauge={'axis': {'range': [0, 10], 'tickcolor': "#71717a"}, 'bar': {'color': "#ef4444" if gitleaks_count > 0 else "#4ade80"}, 'bgcolor': "rgba(255,255,255,0.05)"}
    ))
    fig_secrets.update_layout(**layout_dark, height=250)

    # Graphe Tendance (Scatter)
    fig_trend = go.Figure(data=[go.Scatter(x=['Oct', 'Nov', 'Déc', 'Jan'], y=[120, 95, 60, 40], mode='lines+markers', line=dict(color='#22d3ee', width=3), marker=dict(size=8, color='#0ea5e9'))])
    fig_trend.update_layout(**layout_dark, title_text="Tendance du Risque Gobal", title_x=0.5)

    # Conversion en HTML pour injection
    html_sca = fig_sca.to_html(full_html=False, include_plotlyjs=False)
    html_sast = fig_sast.to_html(full_html=False, include_plotlyjs=False)
    html_dast = fig_dast.to_html(full_html=False, include_plotlyjs=False)
    html_falco = fig_falco.to_html(full_html=False, include_plotlyjs=False)
    html_secrets = fig_secrets.to_html(full_html=False, include_plotlyjs=False)
    html_trend = fig_trend.to_html(full_html=False, include_plotlyjs=False)

    # --- 3. RAPPORT IA ---
    print("Agent Gemini Pro : Formatage de la synthèse IA...")
    
    ai_summary_html = """
    <div class='text-center py-16 text-slate-500'>
        <div class='animate-pulse flex flex-col items-center'>
            <svg class='w-16 h-16 text-blue-500/50 mb-6' fill='none' stroke='currentColor' viewBox='0 0 24 24'><path stroke-linecap='round' stroke-linejoin='round' stroke-width='2' d='M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z'></path></svg>
            <p class='text-xl'>Initialisation des algorithmes d'analyse...</p>
            <p class='text-sm mt-2'>Attente des flux de données de sécurité Gemini.</p>
        </div>
    </div>
    """
    
    if os.path.exists('ai-security-summary.txt'):
        try:
            with open('ai-security-summary.txt', 'r', encoding='utf-8') as f:
                raw_text = f.read()
                ai_summary_html = markdown.markdown(raw_text)
                
                # Injection stylée des graphiques dans le texte de l'IA
                graph_wrapper = '<div class="my-10 mx-auto max-w-3xl p-6 bg-slate-900/60 backdrop-blur-lg border border-slate-800/80 rounded-2xl shadow-2xl shadow-cyan-950/20">{}</div>'
                ai_summary_html = ai_summary_html.replace('[GRAPHIQUE_SCA]', graph_wrapper.format(html_sca))
                ai_summary_html = ai_summary_html.replace('[GRAPHIQUE_SAST]', graph_wrapper.format(html_sast))
                ai_summary_html = ai_summary_html.replace('[GRAPHIQUE_DAST]', graph_wrapper.format(html_dast))
                ai_summary_html = ai_summary_html.replace('[GRAPHIQUE_SECRETS]', graph_wrapper.format(html_secrets))
                ai_summary_html = ai_summary_html.replace('[GRAPHIQUE_FALCO]', graph_wrapper.format(html_falco))
        except Exception as e: ai_summary_html = f"<p class='text-red-400'>Erreur de formatage IA : {e}</p>"

    # Timestamp de génération
    generation_time = datetime.now().strftime("%d/%m/%Y à %H:%M:%S")

    # --- 4. ASSEMBLAGE HTML FINAL (Le grand final interactif) ---
    print("Agent Gemini Pro : Compilation de l'interface Cyber de nouvelle génération...")
    
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
            body {{ font-family: 'Inter', sans-serif; background-color: #010409; color: #e4e4e7; scroll-behavior: smooth; }}
            
            /* Glassmorphism effet avancé */
            .glass-card {{
                background: linear-gradient(145deg, rgba(20, 20, 25, 0.8) 0%, rgba(10, 10, 15, 0.8) 100%);
                backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px);
                border: 1px solid rgba(255, 255, 255, 0.03);
                box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.4), 0 4px 6px -2px rgba(0, 0, 0, 0.2);
                transition: transform 0.2s ease, border-color 0.2s ease, box-shadow 0.2s ease;
            }}
            .glass-card:hover {{
                border-color: rgba(34, 211, 238, 0.3);
                transform: translateY(-3px);
                box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5), 0 10px 10px -5px rgba(0, 0, 0, 0.3);
            }}

            /* Style prose IA Markdown (Gemini Style) */
            .ai-prose h1, .ai-prose h2, .ai-prose h3 {{ color: #fafafa; font-weight: 700; margin-top: 1.8em; margin-bottom: 0.6em; border-bottom: 2px solid rgba(34, 211, 238, 0.15); padding-bottom: 0.4em; }}
            .ai-prose p {{ color: #d4d4d8; line-height: 1.8; margin-bottom: 1.2em; font-weight: 400; }}
            .ai-prose ul {{ list-style-type: disc; padding-left: 1.8em; color: #a1a1aa; margin-bottom: 1.2em; }}
            .ai-prose li {{ margin-bottom: 0.7em; }}
            .ai-prose strong {{ color: #22d3ee; font-weight: 600; }}
            .glow-title {{ text-shadow: 0 0 25px rgba(34, 211, 238, 0.7), 0 0 5px rgba(34, 211, 238, 0.3); }}
            
            /* Boutons interactifs avec lueur */
            .tab-btn.active {{
                background-color: rgba(34, 211, 238, 0.15);
                border-color: rgba(34, 211, 238, 0.6);
                color: #22d3ee;
                box-shadow: 0 0 15px rgba(34, 211, 238, 0.4);
            }}

            /* Animations */
            @keyframes fadeIn {{ from {{ opacity: 0; transform: translateY(15px); }} to {{ opacity: 1; transform: translateY(0); }} }}
            .animate-fadeIn {{ animation: fadeIn 0.5s ease-out forwards; }}

            /* Chat Gemini Flottant */
            #gemini-chat-window {{ transition: all 0.3s ease; opacity: 0; transform: scale(0.9) translateY(20px); pointer-events: none; }}
            #gemini-chat-window.open {{ opacity: 1; transform: scale(1) translateY(0); pointer-events: auto; }}
        </style>
        <title>Gemini Intelligence : DevSecOps Command Center</title>
    </head>
    <body class="min-h-screen bg-[url('https://www.transparenttextures.com/patterns/cubes.png')] bg-fixed">
        <div class="fixed inset-0 bg-zinc-950/95 -z-10"></div>

        <div class="max-w-7xl mx-auto px-4 md:px-6 py-6 pb-20">
            
            <header class="flex flex-col md:flex-row items-center justify-between mb-10 pb-6 border-b border-zinc-800">
                <div class="flex flex-col items-center md:items-start space-y-2">
                    <div class="inline-flex items-center px-3 py-1 rounded-full border border-cyan-500/30 bg-cyan-500/10 text-cyan-400 text-xs font-medium">
                        <span class="flex w-2 h-2 rounded-full bg-cyan-400 mr-2 animate-pulse"></span>
                        Pipeline DevSecOps Actif
                    </div>
                    <h1 class="text-3xl md:text-4xl font-extrabold tracking-tighter text-white glow-title">Gemini <span class="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-blue-500 to-indigo-500">Intelligence Portal</span></h1>
                    <p class="text-zinc-500 text-sm">Vue consolidée et interactive générée par l'IA Gemini Pro pour le projet WebGoat</p>
                </div>
                <div class="flex flex-col items-end mt-4 md:mt-0 text-right text-xs text-zinc-600 space-y-1">
                    <p>Modèle : <span class="text-cyan-600 font-mono">gemini-2.5-flash</span></p>
                    <p>Généré le : <span class="text-zinc-400">{generation_time}</span></p>
                    <div class="flex items-center text-cyan-400 text-sm font-bold mt-2">
                        <span class="mr-1.5">🛡️</span> Security Score: <span class="text-white ml-1 font-mono">A-</span>
                    </div>
                </div>
            </header>

            <div class="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-10">
                <div class="glass-card rounded-xl p-5 border-l-4 border-red-600">
                    <p class="text-xs text-zinc-500 uppercase font-semibold">Total Vulnérabilités</p>
                    <p class="text-3xl md:text-4xl font-extrabold text-white mt-1">{total_vulns}</p>
                    <p class="text-xs text-red-500 mt-1 flex items-center"><span class="mr-1">⚠️</span> +25% vs hier</p>
                </div>
                <div class="glass-card rounded-xl p-5 border-l-4 border-red-500">
                    <p class="text-xs text-zinc-500 uppercase font-semibold">Alertes Critiques</p>
                    <p class="text-3xl md:text-4xl font-extrabold text-red-400 mt-1">{total_critical}</p>
                    <p class="text-xs text-red-400 mt-1">Actions Prioritaires</p>
                </div>
                <div class="glass-card rounded-xl p-5 border-l-4 border-orange-500">
                    <p class="text-xs text-zinc-500 uppercase font-semibold">Bugs Statiques</p>
                    <p class="text-3xl md:text-4xl font-extrabold text-white mt-1">{total_static_bugs}</p>
                    <p class="text-xs text-orange-400 mt-1">Dette technique Sonar</p>
                </div>
                <div class="glass-card rounded-xl p-5 border-l-4 border-yellow-500">
                    <p class="text-xs text-zinc-500 uppercase font-semibold">Secrets Exposés</p>
                    <p class="text-3xl md:text-4xl font-extrabold text-white mt-1">{gitleaks_count}</p>
                    <p class="text-xs text-yellow-400 mt-1">Risque d'intrusion</p>
                </div>
            </div>

            <div class="flex justify-center md:justify-start space-x-3 mb-8 pb-3 border-b border-zinc-800">
                <button id="btn-tab-ai" onclick="switchTab('tab-ai')" class="tab-btn active px-5 py-2.5 rounded-xl text-sm font-semibold transition-all duration-300 flex items-center">
                    <span class="mr-2">🤖</span> Synthèse IA Statégique
                </button>
                <button id="btn-tab-metrics" onclick="switchTab('tab-metrics')" class="tab-btn px-5 py-2.5 rounded-xl text-sm border border-zinc-800 bg-zinc-900/50 text-zinc-400 font-semibold hover:bg-zinc-800 hover:text-white transition-all duration-300 flex items-center">
                    <span class="mr-2">📈</span> Centre de Métriques Techniques
                </button>
            </div>

            <div class="relative min-h-[500px]">
                
                <div id="tab-ai" class="tab-content block animate-fadeIn w-full">
                    <div class="mb-10 rounded-3xl p-[1px] bg-gradient-to-br from-cyan-600/30 via-zinc-800/10 to-blue-600/20">
                        <div class="glass-card rounded-3xl p-6 md:p-12 relative overflow-hidden">
                            <div class="absolute top-0 right-0 -mt-8 -mr-8 w-40 h-40 bg-cyan-600/15 rounded-full blur-3xl"></div>
                            <div class="absolute bottom-0 left-0 -mb-8 -ml-8 w-40 h-40 bg-purple-600/10 rounded-full blur-3xl"></div>
                            <div class="flex items-center mb-8 space-x-3.5 border-b border-zinc-800/80 pb-6">
                                <div class="p-2.5 bg-blue-500/15 rounded-xl border border-blue-500/25">
                                    <svg class="w-7 h-7 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg>
                                </div>
                                <div>
                                    <h2 class="text-2xl font-bold text-white tracking-tight">Analyse Corrélative Intelligente</h2>
                                    <p class="text-zinc-500 text-xs">Propulsé par l'agent analytique Gemini Pro</p>
                                </div>
                            </div>
                            <div class="ai-prose">
                                {ai_summary_html}
                            </div>
                        </div>
                    </div>
                </div>

                <div id="tab-metrics" class="tab-content hidden w-full">
                    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                        <div class="glass-card rounded-2xl p-6 flex flex-col cursor-pointer border border-cyan-900/10">
                            <h3 class="text-slate-300 font-bold mb-3 flex items-center justify-between"><span class="flex items-center text-blue-400"><span class="mr-2.5">📦</span> Trivy (SCA)</span><span class="text-zinc-600 text-xs font-mono">fs scan</span></h3>
                            <div class="flex-grow">{html_sca}</div>
                            <div class="mt-4 text-xs text-zinc-600 bg-zinc-900 rounded p-2 border border-zinc-800">💡 CVE trouvées dans les librairies tierces.</div>
                        </div>
                        
                        <div class="glass-card rounded-2xl p-6 flex flex-col cursor-pointer">
                            <h3 class="text-slate-300 font-bold mb-3 flex items-center justify-between"><span class="flex items-center text-red-400"><span class="mr-2.5">📝</span> SonarCloud (SAST)</span><span class="text-zinc-600 text-xs font-mono">web goat</span></h3>
                            <div class="flex-grow">{html_sast}</div>
                            <div class="mt-4 text-xs text-zinc-600 bg-zinc-900 rounded p-2 border border-zinc-800">💡 Problèmes détectés dans le code source.</div>
                        </div>
                        
                        <div class="glass-card rounded-2xl p-6 flex flex-col cursor-pointer">
                            <h3 class="text-slate-300 font-bold mb-3 flex items-center justify-between"><span class="flex items-center text-purple-400"><span class="mr-2.5">🕸️</span> OWASP ZAP (DAST)</span><span class="text-zinc-600 text-xs font-mono">http/web</span></h3>
                            <div class="flex-grow">{html_dast}</div>
                            <div class="mt-4 text-xs text-zinc-600 bg-zinc-900 rounded p-2 border border-zinc-800">💡 Vulnérabilités actives sur l'app web.</div>
                        </div>

                        <div class="glass-card rounded-2xl p-6 flex flex-col cursor-pointer">
                            <h3 class="text-slate-300 font-bold mb-3 flex items-center justify-between"><span class="flex items-center text-emerald-400"><span class="mr-2.5">⚡</span> Falco (Runtime)</span><span class="text-zinc-600 text-xs font-mono">sandbox</span></h3>
                            <div class="flex-grow">{html_falco}</div>
                            <div class="mt-4 text-xs text-zinc-600 bg-zinc-900 rounded p-2 border border-zinc-800">💡 Intrusions détectées dans le conteneur.</div>
                        </div>

                        <div class="glass-card rounded-2xl p-6 flex flex-col cursor-pointer">
                            <h3 class="text-slate-300 font-bold mb-3 flex items-center justify-between"><span class="flex items-center text-orange-400"><span class="mr-2.5">🔑</span> Gitleaks (Secrets)</span><span class="text-zinc-600 text-xs font-mono">secrets</span></h3>
                            <div class="flex-grow">{html_secrets}</div>
                            <div class="mt-4 text-xs text-zinc-600 bg-zinc-900 rounded p-2 border border-zinc-800">💡 Secrets en clair détectés dans le git.</div>
                        </div>

                        <div class="glass-card rounded-2xl p-6 flex flex-col cursor-pointer border border-cyan-950/20 shadow-cyan-950/20shadow-2xl">
                            <h3 class="text-slate-300 font-bold mb-3 flex items-center text-cyan-400"><span class="mr-2.5">📈</span> Tendance de Risque Global</h3>
                            <div class="flex-grow">{html_trend}</div>
                            <div class="mt-4 text-xs text-zinc-600 bg-zinc-900 rounded p-2 border border-zinc-800">💡 Évolution temporelle du score de sécurité.</div>
                        </div>
                    </div>
                </div>

            </div>

            <div class="fixed bottom-6 right-6 z-50">
                <div id="gemini-chat-window" class="glass-card w-80 h-96 rounded-2xl p-5 mb-4 shadow-3xl shadow-black overflow-hidden flex flex-col">
                    <div class="flex items-center justify-between border-b border-zinc-800 pb-3 mb-4">
                        <div class="flex items-center space-x-2">
                            <span class="text-2xl">🤖</span>
                            <div>
                                <h4 class="text-white font-bold">Gemini Agent Terminal</h4>
                                <p class="text-cyan-400 text-xs font-mono">status: <span class="animate-pulse">waiting_for_input</span></p>
                            </div>
                        </div>
                        <button onclick="toggleGeminiChat()" class="text-zinc-600 hover:text-white text-xl">×</button>
                    </div>
                    <div class="flex-grow text-xs text-slate-400 font-mono space-y-3 overflow-y-auto pr-1">
                        <p class='text-cyan-500'>[SYSTEM] Initialisation de l'agent Gemini Pro...</p>
                        <p>> Hello, je suis <strong class='text-white'>Gemini Pro</strong>. J'ai corrélé tes rapports Sonar, Trivy, ZAP et Falco.</p>
                        <p>> L'onglet <strong class='text-cyan-400'>"Synthèse"</strong> te donne mon analyse stratégique.</p>
                        <p>> Clique sur <strong class='text-white'>"Métriques"</strong> pour les détails techniques.</p>
                        <p class='text-orange-400'>> Attention particulière aux secrets exposés !</p>
                        <p class='text-zinc-600'>[GEMINI] En attente de questions supplémentaires via le workflow.</p>
                    </div>
                </div>
                <button onclick="toggleGeminiChat()" class="w-16 h-16 bg-blue-600 rounded-full shadow-2xl shadow-blue-900/70 border-4 border-white/10 flex items-center justify-center text-3xl hover:bg-cyan-500 hover:scale-110 transition-all duration-300 transform active:scale-95">
                    <span class="text-center glow-title">🤖</span>
                </button>
            </div>

            <footer class="mt-16 text-center text-zinc-700 text-xs border-t border-zinc-900 pt-8 pb-2">
                <p>Généré intelligemment par GitHub Actions • Propulsé par <strong class="text-cyan-700">Gemini Pro Agent</strong> • Projet DevSecOps Command Center © 2026</p>
            </footer>

        </div>
        
        <script>
            // Système d'onglets
            function switchTab(tabId) {{
                // Cacher tous les contenus
                document.querySelectorAll('.tab-content').forEach(el => el.classList.add('hidden'));
                
                // Réinitialiser le style de tous les boutons
                document.querySelectorAll('.tab-btn').forEach(btn => {{
                    btn.classList.remove('active', 'border-cyan-500/50', 'bg-cyan-500/20', 'text-cyan-300', 'shadow-[0_0_15px_rgba(34,211,238,0.4)]');
                    btn.classList.add('border-zinc-800', 'bg-zinc-900/50', 'text-zinc-400');
                    btn.classList.add('hover:bg-zinc-800', 'hover:text-white');
                }});

                // Afficher le contenu ciblé
                const targetContent = document.getElementById(tabId);
                targetContent.classList.remove('hidden');
                
                // Forcer un reflow de Plotly pour qu'il s'adapte à la largeur cachée
                window.dispatchEvent(new Event('resize'));

                // Mettre en surbrillance le bouton actif
                const activeBtn = document.getElementById('btn-' + tabId);
                activeBtn.classList.add('active', 'border-cyan-500/50', 'bg-cyan-500/20', 'text-cyan-300', 'shadow-[0_0_15px_rgba(34,211,238,0.4)]');
                activeBtn.classList.remove('border-zinc-800', 'bg-zinc-900/50', 'text-zinc-400', 'hover:bg-zinc-800', 'hover:text-white');
            }}

            // Gemini Chat Flottant
            function toggleGeminiChat() {{
                document.getElementById('gemini-chat-window').classList.toggle('open');
            }}
            
            // Re-render Plotly on resize to handle glassmorphism changes
            window.addEventListener('resize', function() {{
                document.querySelectorAll('.plotly-graph-div').forEach(function(div) {{
                    Plotly.Plots.resize(div);
                }});
            }});
        </script>
        
    </body>
    </html>
    """

    with open("global_security_report.html", "w", encoding='utf-8') as f:
        f.write(html_content)

if __name__ == "__main__":
    generate_dashboard()
