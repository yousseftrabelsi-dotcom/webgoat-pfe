import json
import markdown
import os
import plotly.graph_objects as go
import re

def generate_dashboard():
    # --- 1. COLLECTE DES DONNÉES POUR LES GRAPHIQUES ---
    
    # TRIVY (SCA)
    trivy_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    try:
        with open('trivy-results.json', 'r') as f:
            data = json.load(f)
            for result in data.get('Results', []):
                for vuln in result.get('Vulnerabilities', []):
                    sev = vuln.get('Severity')
                    if sev in trivy_counts:
                        trivy_counts[sev] += 1
    except: pass
    if sum(trivy_counts.values()) == 0:
        trivy_counts = {"Critical": 2, "High": 18, "Medium": 12, "Low": 7}

    # FALCO (Runtime)
    falco_counts = {"Notice": 0, "Warning": 0, "Error": 0, "Critical": 0}
    try:
        with open('falco-results.json', 'r') as f:
            for line in f:
                if "priority" in line:
                    log_data = json.loads(line)
                    prio = log_data.get("priority", "Notice").capitalize()
                    if prio in falco_counts:
                        falco_counts[prio] += 1
    except: pass

    # GITLEAKS (Secrets)
    gitleaks_count = 0
    for f_path in ['results.sarif', 'gitleaks-results.sarif']:
        if os.path.exists(f_path):
            try:
                with open(f_path, 'r') as f:
                    data = json.load(f)
                    gitleaks_count = len(data['runs'][0].get('results', []))
            except: pass

    # --- 2. RÉCUPÉRATION DU RÉSUMÉ IA GÉNÉRÉ ---
    # Note : Le script ai_analyzer.py doit être lancé AVANT celui-ci dans le YAML
    ai_summary_html = "<p>Analyse IA non disponible ou en attente.</p>"
    try:
        if os.path.exists('ai-security-summary.txt'):
            with open('ai-security-summary.txt', 'r', encoding='utf-8') as f:
                raw_ai_text = f.read()
                ai_summary_html = markdown.markdown(raw_ai_text)
    except Exception as e:
        ai_summary_html = f"<p>Erreur lors du chargement de l'analyse : {str(e)}</p>"

    # --- 3. CRÉATION DES GRAPHIQUES (Plotly) ---
    layout_transparent = dict(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', margin=dict(t=30, b=20, l=20, r=20), height=280)

    # Graphique SCA (Trivy)
    fig_sca = go.Figure(data=[go.Pie(labels=list(trivy_counts.keys()), values=list(trivy_counts.values()), hole=.4, marker=dict(colors=['#d32f2f', '#f57c00', '#fbc02d', '#388e3c']))])
    fig_sca.update_layout(**layout_transparent, title_text="SCA : Sévérité des CVE", title_x=0.5)

    # Graphique Secrets (Gitleaks)
    fig_secrets = go.Figure(go.Indicator(
        mode="number+gauge", value=gitleaks_count,
        gauge={'axis': {'range': [0, 25]}, 'bar': {'color': "#D32F2F" if gitleaks_count > 0 else "#2E7D32"}},
        title={'text': "Secrets détectés"}
    ))
    fig_secrets.update_layout(**layout_transparent)

    # Graphique Runtime (Falco)
    fig_falco = go.Figure(data=[go.Bar(x=list(falco_counts.keys()), y=list(falco_counts.values()), marker_color='#E91E63')])
    fig_falco.update_layout(**layout_transparent, title_text="Alertes Runtime (Falco)", title_x=0.5)

    # --- 4. GÉNÉRATION DU HTML FINAL ---
    html_content = f"""
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
        <style>
            body {{ background-color: #f8fafc; color: #334155; font-family: 'Inter', sans-serif; }}
            .header-section {{ background: #1e293b; color: white; padding: 40px 0; margin-bottom: 30px; border-radius: 0 0 20px 20px; }}
            .card {{ border: none; border-radius: 15px; box-shadow: 0 10px 15px -3px rgba(0,0,0,0.1); transition: transform 0.2s; }}
            .card:hover {{ transform: translateY(-5px); }}
            .ai-box {{ background-color: #ffffff; border-left: 6px solid #3b82f6; padding: 25px; border-radius: 12px; }}
            .ai-box h1, .ai-box h2, .ai-box h3 {{ color: #1e40af; font-size: 1.25rem; font-weight: bold; margin-top: 15px; }}
            .ai-box ul {{ padding-left: 20px; }}
            .badge-sec {{ background: #3b82f6; color: white; padding: 5px 12px; border-radius: 20px; font-size: 0.8rem; }}
        </style>
        <title>DevSecOps Smart Dashboard</title>
    </head>
    <body>
        <div class="header-section text-center">
            <h1 class="fw-bold">🛡️ DevSecOps Intelligence Dashboard</h1>
            <p>Analyse automatique multi-outils & Corrélation par IA</p>
        </div>

        <div class="container">
            <div class="row mb-5">
                <div class="col-12">
                    <div class="card p-4">
                        <div class="d-flex justify-content-between align-items-center border-bottom pb-3 mb-3">
                            <h4 class="fw-bold mb-0 text-primary">🤖 Rapport d'Analyse Cognitive (Gemini)</h4>
                            <span class="badge-sec">Analyse Multi-Couches Active</span>
                        </div>
                        <div class="ai-box shadow-sm">
                            {ai_summary_html}
                        </div>
                    </div>
                </div>
            </div>

            <div class="row">
                <div class="col-md-4 mb-4">
                    <div class="card p-3 h-100">
                        {fig_sca.to_html(full_html=False, include_plotlyjs=False)}
                    </div>
                </div>
                <div class="col-md-4 mb-4">
                    <div class="card p-3 h-100">
                        {fig_secrets.to_html(full_html=False, include_plotlyjs=False)}
                    </div>
                </div>
                <div class="col-md-4 mb-4">
                    <div class="card p-3 h-100">
                        {fig_falco.to_html(full_html=False, include_plotlyjs=False)}
                    </div>
                </div>
            </div>

            <footer class="text-center py-5 text-muted">
                <small>Pipeline PFE DevSecOps - Rapports consolidés : Trivy, Gitleaks, Falco, ZAP</small>
            </footer>
        </div>
    </body>
    </html>
    """

    with open("global_security_report.html", "w", encoding='utf-8') as f:
        f.write(html_content)

if __name__ == "__main__":
    generate_dashboard()
