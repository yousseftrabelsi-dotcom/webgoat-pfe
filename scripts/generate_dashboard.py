import json
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import os

def generate_dashboard():
    # --- 1. COLLECTE DES DONNÉES (SCA, SAST, DAST, IA) ---
    
    # TRIVY (SCA) - Lecture réelle du JSON
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

    # AI SUMMARY - Lecture du rapport Gemini
    ai_summary = "L'analyse IA est en cours de chargement..."
    try:
        with open('ai-security-summary.txt', 'r', encoding='utf-8') as f:
            ai_summary = f.read().replace('\n', '<br>')
    except: pass

    # --- 2. CRÉATION DES GRAPHIQUES MODERNES ---

    # A. Pie Chart : Répartition SCA (Trivy)
    fig_sca = go.Figure(data=[go.Pie(
        labels=list(trivy_counts.keys()), 
        values=list(trivy_counts.values()), 
        hole=.5,
        marker=dict(colors=['#d32f2f', '#f57c00', '#fbc02d', '#388e3c'])
    )])
    fig_sca.update_layout(showlegend=True, margin=dict(t=0, b=0, l=0, r=0), height=300)

    # B. Bar Chart : SonarCloud (SAST)
    # Données basées sur tes captures d'écran
    fig_sast = go.Figure(data=[go.Bar(
        x=['Bugs', 'Vulnerabilities', 'Security Hotspots'], 
        y=[375, 40, 66],
        marker_color=['#1976D2', '#D32F2F', '#FFA000']
    )])
    fig_sast.update_layout(margin=dict(t=20, b=20, l=20, r=20), height=300)

    # C. Column Chart : ZAP Alert Types (DAST)
    # Données basées sur ton dernier scan
    zap_labels = ['CORS Policy', 'CSRF Tokens', 'Session Mgmt', 'Auth Req']
    zap_values = [11, 5, 1, 1]
    fig_dast = go.Figure(data=[go.Bar(
        x=zap_labels, 
        y=zap_values,
        marker_color='#673AB7'
    )])
    fig_dast.update_layout(margin=dict(t=20, b=20, l=20, r=20), height=300)

    # --- 3. GÉNÉRATION DU HTML AVEC DESIGN MODERNE (BOOTSTRAP) ---
    
    html_content = f"""
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
        <style>
            body {{ background-color: #f8f9fa; color: #333; }}
            .card {{ border: none; box-shadow: 0 4px 12px rgba(0,0,0,0.1); border-radius: 12px; transition: 0.3s; margin-bottom: 20px; }}
            .card:hover {{ transform: translateY(-5px); }}
            .header-section {{ background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%); color: white; padding: 40px 0; margin-bottom: 40px; border-radius: 0 0 25px 25px; }}
            .insight-box {{ background-color: #ffffff; border-left: 5px solid #3b82f6; padding: 20px; border-radius: 8px; }}
            .badge-custom {{ font-size: 0.9em; padding: 8px 15px; border-radius: 20px; }}
        </style>
        <title>DevSecOps Dashboard - PFE</title>
    </head>
    <body>
        <div class="header-section text-center">
            <h1>🛡️ DevSecOps Executive Dashboard</h1>
            <p class="lead">Analyse de sécurité consolidée pour le projet <strong>WebGoat-PFE</strong></p>
            <span class="badge bg-light text-dark badge-custom">Date: 14 Avril 2026</span>
        </div>

        <div class="container">
            <div class="row">
                <div class="col-md-4">
                    <div class="card p-3">
                        <h5 class="text-center">SCA : Sécurité des Dépendances</h5>
                        <p class="text-muted small text-center">Outil : Trivy</p>
                        {fig_sca.to_html(full_html=False, include_plotlyjs=False)}
                        <div class="mt-2 small text-center">
                            Focus : <strong>{trivy_counts['Critical']}</strong> vulnérabilités critiques détectées.
                        </div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card p-3">
                        <h5 class="text-center">SAST : Analyse Statique</h5>
                        <p class="text-muted small text-center">Outil : SonarCloud</p>
                        {fig_sast.to_html(full_html=False, include_plotlyjs=False)}
                        <div class="mt-2 small text-center">
                            Note de sécurité : <span class="text-danger font-weight-bold">E (Critique)</span>
                        </div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card p-3">
                        <h5 class="text-center">DAST : Analyse Dynamique</h5>
                        <p class="text-muted small text-center">Outil : OWASP ZAP</p>
                        {fig_dast.to_html(full_html=False, include_plotlyjs=False)}
                        <div class="mt-2 small text-center">
                            Alerte majeure : <strong>CORS Misconfiguration</strong> (11 occurrences)
                        </div>
                    </div>
                </div>
            </div>

            <div class="row mt-4">
                <div class="col-12">
                    <div class="card p-4">
                        <h3 class="border-bottom pb-2 mb-3">🤖 Intelligence Artificielle & Synthèse</h3>
                        <div class="insight-box">
                            <p class="font-italic">{ai_summary}</p>
                        </div>
                    </div>
                </div>
            </div>
            
            <footer class="text-center my-5 text-muted small">
                Dashboard généré automatiquement par le pipeline DevSecOps GitHub Actions.
            </footer>
        </div>
    </body>
    </html>
    """

    with open("global_security_report.html", "w", encoding='utf-8') as f:
        f.write(html_content)

if __name__ == "__main__":
    generate_dashboard()
