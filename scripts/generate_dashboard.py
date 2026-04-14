import json
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import os

def generate_dashboard():
    # --- 1. RÉCUPÉRATION DES DONNÉES ---
    
    # Données Trivy (SCA)
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

    # Lecture du rapport de l'IA (Gemini)
    ai_summary = "Rapport IA non disponible."
    try:
        with open('ai-security-summary.txt', 'r', encoding='utf-8') as f:
            ai_summary = f.read().replace('\n', '<br>') # Formattage pour le HTML
    except: pass

    # --- 2. CRÉATION DES GRAPHIQUES ---
    
    fig = make_subplots(
        rows=2, cols=2,
        specs=[[{"type": "domain"}, {"type": "bar"}],
               [{"type": "indicator"}, {"type": "bar"}]],
        subplot_titles=("Vulnérabilités Dépendances (Trivy)", "Métriques Statiques (SonarCloud)", 
                        "Score de Santé Sécurité", "Alertes Dynamiques (ZAP)")
    )

    # Graphique SCA (Trivy)
    fig.add_trace(go.Pie(labels=list(trivy_counts.keys()), values=list(trivy_counts.values()), hole=.4), row=1, col=1)

    # Métriques Sonar (Exemple basé sur tes captures)
    fig.add_trace(go.Bar(x=['Bugs', 'Vulnerabilities', 'Hotspots'], y=[375, 40, 66], marker_color='red'), row=1, col=2)

    # Jauge de conformité
    fig.add_trace(go.Indicator(mode="gauge+number", value=45, title={'text': "Conformité %"}), row=2, col=1)

    # Alertes ZAP (DAST)
    fig.add_trace(go.Bar(x=['Injection', 'CORS', 'CSRF', 'Sensitive'], y=[2, 11, 5, 3], marker_color='orange'), row=2, col=2)

    fig.update_layout(height=900, title_text="Tableau de Bord DevSecOps Interactif - Projet PFE", showlegend=True)

    # --- 3. GÉNÉRATION DU FICHIER HTML ---
    
    # On génère le HTML des graphiques
    graph_html = fig.to_html(full_html=False, include_plotlyjs='cdn')

    # On crée une structure HTML complète avec l'analyse de l'IA en dessous
    html_template = f"""
    <html>
        <head>
            <title>DevSecOps Dashboard</title>
            <style>
                body {{ font-family: sans-serif; margin: 20px; background-color: #f4f4f9; }}
                .ai-box {{ background-color: #fff; border-left: 5px solid #4285f4; padding: 20px; margin-top: 20px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
                h2 {{ color: #4285f4; }}
            </style>
        </head>
        <body>
            <h1>Rapport de Sécurité Consolidé - WebGoat</h1>
            <div>{graph_html}</div>
            <div class="ai-box">
                <h2>🤖 Analyse Intelligente (Gemini AI)</h2>
                <p>{ai_summary}</p>
            </div>
        </body>
    </html>
    """

    with open("global_security_report.html", "w", encoding='utf-8') as f:
        f.write(html_template)
    
    print("Dashboard généré : global_security_report.html")

if __name__ == "__main__":
    generate_dashboard()
