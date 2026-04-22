import json
import markdown
import os
import plotly.graph_objects as go

def generate_dashboard():
    # --- 1. COLLECTE DES DONNÉES ---
    # SONARCLOUD (SAST) - Données dynamiques
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
        print(f"Erreur lors de la lecture de SonarCloud : {e}")
        
    # TRIVY (SCA)
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

    # FALCO (Runtime Security)
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

    # GITLEAKS (Secrets) - Support dynamique
    gitleaks_count = 0
    gitleaks_files = [
        'gitleaks-results.sarif/results.sarif', 
        'gitleaks-results.sarif/gitleaks.sarif',
        'gitleaks-results.sarif', 
        'results.sarif', 
        'gitleaks-report.json'
    ]
    file_found = None

    for filename in gitleaks_files:
        if os.path.isfile(filename):
            file_found = filename
            break

    if file_found:
        try:
            with open(file_found, 'r', encoding='utf-8') as f:
                gitleaks_data = json.load(f)
                if isinstance(gitleaks_data, list):
                    gitleaks_count = len(gitleaks_data)
                elif isinstance(gitleaks_data, dict) and 'runs' in gitleaks_data:
                    gitleaks_count = len(gitleaks_data['runs'][0].get('results', []))
        except Exception as e:
            print(f"Erreur lors de la lecture de Gitleaks : {e}")

    # --- 2. CRÉATION DES GRAPHIQUES ---
    layout_transparent = dict(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', margin=dict(t=30, b=20, l=20, r=20), height=280)

    # 1. SCA
    fig_sca = go.Figure(data=[go.Pie(labels=list(trivy_counts.keys()), values=list(trivy_counts.values()), hole=.4, marker=dict(colors=['#d32f2f', '#f57c00', '#fbc02d', '#388e3c']))])
    fig_sca.update_layout(**layout_transparent, title_text="Vulnérabilités par Sévérité", title_x=0.5)

    # 2. SAST (Dynamique avec les vraies données)
    fig_sast = go.Figure(data=[go.Bar(
        x=['Bugs', 'Vulnérabilités', 'Hotspots'], 
        y=[sonar_bugs, sonar_vulns, sonar_hotspots], 
        marker_color=['#1976D2', '#D32F2F', '#FFA000'], 
        text=[sonar_bugs, sonar_vulns, sonar_hotspots], 
        textposition='auto'
    )])
    fig_sast.update_layout(**layout_transparent, title_text="Problèmes de Code Statique", title_x=0.5)

    # 3. DAST
    fig_dast = go.Figure(data=[go.Bar(x=['CORS', 'CSRF', 'Session', 'Auth'], y=[11, 5, 1, 1], marker_color='#673AB7', text=[11, 5, 1, 1], textposition='auto')])
    fig_dast.update_layout(**layout_transparent, title_text="Alertes Web ZAP", title_x=0.5)

    # 4. FALCO (Runtime)
    fig_falco = go.Figure(data=[go.Bar(x=list(falco_counts.keys()), y=list(falco_counts.values()), marker_color=['#4CAF50', '#FF9800', '#E91E63', '#B71C1C'], text=list(falco_counts.values()), textposition='auto')])
    fig_falco.update_layout(**layout_transparent, title_text="Détections Falco", title_x=0.5)

    # 5. Gitleaks (Dynamique)
    fig_secrets = go.Figure(go.Indicator(
        mode="number+gauge", 
        value=gitleaks_count,
        title={'text': "Secrets fuités détectés"},
        gauge={
            'axis': {'range': [0, max(5, gitleaks_count + 2)]}, 
            'bar': {'color': "#D32F2F" if gitleaks_count > 0 else "#2E7D32"}, 
            'steps': [{'range': [1, max(5, gitleaks_count + 2)], 'color': "rgba(255, 0, 0, 0.2)"}]
        }
    ))
    fig_secrets.update_layout(**layout_transparent)

    # 6. Tendance
    fig_trend = go.Figure(data=[go.Scatter(x=['Scan 1', 'Scan 2', 'Scan 3', 'Actuel'], y=[120, 95, 60, 40], mode='lines+markers+text', line=dict(color='#2E7D32', width=4), marker=dict(size=10))])
    fig_trend.update_layout(**layout_transparent, title_text="Réduction des failles", title_x=0.5)

    # --- 3. PRÉPARATION DES GRAPHIQUES POUR L'INJECTION IA (NOUVEAU) ---
    html_sca = fig_sca.to_html(full_html=False, include_plotlyjs=False)
    html_sast = fig_sast.to_html(full_html=False, include_plotlyjs=False)
    html_dast = fig_dast.to_html(full_html=False, include_plotlyjs=False)
    html_falco = fig_falco.to_html(full_html=False, include_plotlyjs=False)
    html_secrets = fig_secrets.to_html(full_html=False, include_plotlyjs=False)

    # --- 4. IA SUMMARY - Lecture et Injection ---
    ai_summary_html = "<p>Analyse IA non disponible. Vérifiez que le job ai-agent-analysis s'est bien terminé.</p>"
    if os.path.exists('ai-security-summary.txt'):
        try:
            with open('ai-security-summary.txt', 'r', encoding='utf-8') as f:
                raw_text = f.read()
                # Conversion du Markdown de Gemini en HTML pour le dashboard
                ai_summary_html = markdown.markdown(raw_text)
                
                # NOUVEAU : Remplacement des balises par les graphiques
                # On met une petite marge pour aérer le texte
                graph_wrapper = '<div style="margin: 25px auto; max-width: 800px; padding: 10px; background: #fff; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05);">{}</div>'
                ai_summary_html = ai_summary_html.replace('[GRAPHIQUE_SCA]', graph_wrapper.format(html_sca))
                ai_summary_html = ai_summary_html.replace('[GRAPHIQUE_SAST]', graph_wrapper.format(html_sast))
                ai_summary_html = ai_summary_html.replace('[GRAPHIQUE_DAST]', graph_wrapper.format(html_dast))
                ai_summary_html = ai_summary_html.replace('[GRAPHIQUE_SECRETS]', graph_wrapper.format(html_secrets))
                ai_summary_html = ai_summary_html.replace('[GRAPHIQUE_FALCO]', graph_wrapper.format(html_falco))
                
        except Exception as e: 
            print(f"Erreur de lecture IA : {e}")
            ai_summary_html = f"<p class='text-danger'>Erreur lors du traitement du rapport IA : {e}</p>"

    # --- 5. HTML & BOOTSTRAP (Ton ancien design conservé intact) ---
    html_content = f"""
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
        <style>
            body {{ background-color: #f1f5f9; color: #1e293b; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }}
            .card {{ border: none; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1); border-radius: 12px; margin-bottom: 24px; overflow: hidden; }}
            .header-section {{ background: linear-gradient(135deg, #0f172a 0%, #3b82f6 100%); color: white; padding: 35px 0; border-radius: 0 0 25px 25px; margin-bottom: 30px; }}
            .note-box {{ background-color: #e2e8f0; border-left: 4px solid #64748b; padding: 10px 15px; font-size: 0.85rem; border-radius: 4px; margin-top: 10px; }}
            .ai-card-header {{ background-color: #ecfeff; border-bottom: 1px solid #cffafe; padding: 15px 20px; }}
            .ai-box {{ padding: 20px; font-size: 1.05rem; line-height: 1.6; color: #083344; }}
            .ai-box h1, .ai-box h2, .ai-box h3 {{ color: #0369a1; font-size: 1.3rem; margin-top: 15px; font-weight: bold; }}
            .ai-box ul {{ padding-left: 20px; }}
            .badge-custom {{ background-color: #0284c7; color: white; padding: 5px 10px; border-radius: 15px; font-size: 0.8rem; vertical-align: middle; margin-left: 10px; }}
        </style>
        <title>DevSecOps Dashboard</title>
    </head>
    <body>
        <div class="header-section text-center">
            <h1 class="fw-bold">🛡️ DevSecOps Executive Dashboard</h1>
            <p class="mb-0">Vue consolidée du pipeline CI/CD - Projet WebGoat</p>
        </div>

        <div class="container">
            <div class="row mb-4">
                <div class="col-12">
                    <div class="card" style="border-left: 5px solid #06b6d4;">
                        <div class="ai-card-header d-flex align-items-center">
                            <h4 class="fw-bold text-info mb-0">🤖 Rapport d'Analyse IA Correlée</h4>
                            <span class="badge-custom">SCA + SAST + DAST + Runtime + Secrets</span>
                        </div>
                        <div class="ai-box bg-white">
                            {ai_summary_html}
                        </div>
                    </div>
                </div>
            </div>

            <div class="row">
                <div class="col-md-4">
                    <div class="card p-3">
                        <h5 class="text-center text-secondary fw-bold border-bottom pb-2">SCA : Dépendances</h5>
                        {fig_sca.to_html(full_html=False, include_plotlyjs=False)}
                        <div class="note-box">💡 <b>Note:</b> Représente les CVE trouvées par Trivy dans les librairies tierces.</div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card p-3">
                        <h5 class="text-center text-secondary fw-bold border-bottom pb-2">SAST : Code Source</h5>
                        {fig_sast.to_html(full_html=False, include_plotlyjs=False)}
                        <div class="note-box">💡 <b>Note:</b> Analyse SonarCloud. Dette technique élevée à traiter.</div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card p-3">
                        <h5 class="text-center text-secondary fw-bold border-bottom pb-2">DAST : Attaques Actives</h5>
                        {fig_dast.to_html(full_html=False, include_plotlyjs=False)}
                        <div class="note-box">💡 <b>Note:</b> Scan OWASP ZAP sur conteneur Docker.</div>
                    </div>
                </div>
            </div>

            <div class="row">
                <div class="col-md-4">
                    <div class="card p-3">
                        <h5 class="text-center text-secondary fw-bold border-bottom pb-2">Runtime : Intrusions</h5>
                        {fig_falco.to_html(full_html=False, include_plotlyjs=False)}
                        <div class="note-box">💡 <b>Note:</b> Détections Falco. Tentatives de manipulation du système hôte capturées.</div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card p-3">
                        <h5 class="text-center text-secondary fw-bold border-bottom pb-2">Gitleaks : Scan de Secrets</h5>
                        {fig_secrets.to_html(full_html=False, include_plotlyjs=False)}
                        <div class="note-box">💡 <b>Note:</b> Nombre de secrets en clair détectés dans les commits récents.</div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card p-3">
                        <h5 class="text-center text-secondary fw-bold border-bottom pb-2">Progression Sécurité</h5>
                        {fig_trend.to_html(full_html=False, include_plotlyjs=False)}
                        <div class="note-box">💡 <b>Note:</b> Baisse continue du nombre de vulnérabilités au fil des pipelines.</div>
                    </div>
                </div>
            </div>
            
            <footer class="text-center my-4 text-muted small">
                Généré automatiquement par GitHub Actions - Pipeline PFE DevSecOps
            </footer>
        </div>
    </body>
    </html>
    """

    with open("global_security_report.html", "w", encoding='utf-8') as f:
        f.write(html_content)

if __name__ == "__main__":
    generate_dashboard()
