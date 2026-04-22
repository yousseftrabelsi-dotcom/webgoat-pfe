import os
import time
from google import genai

print("Démarrage de l'analyse IA corrélée...")

client = genai.Client()

# 1. Dictionnaire de tous les rapports attendus du pipeline
fichiers_rapports = {
    "SonarCloud (SAST - Qualité du code)": "sonar-results.json",
    "Trivy (SCA - Dépendances)": "trivy-results.json",
    "Gitleaks (Recherche de Secrets)": "results.sarif",
    "ZAP (DAST - Analyse Dynamique)": "report_html.html",
    "Falco (Sécurité Runtime)": "falco-results.json"
}

contexte_global = ""

# 2. Lecture dynamique de tous les fichiers existants
for outil, fichier in fichiers_rapports.items():
    if os.path.exists(fichier):
        print(f"-> Intégration du rapport : {outil}...")
        try:
            with open(fichier, 'r', encoding='utf-8') as f:
                contenu = f.read()
                # CORRECTION : On réduit drastiquement la limite à 10 000 caractères
                # pour éviter de surcharger l'API avec du code HTML/JSON inutile
                contexte_global += f"\n\n=== RÉSULTATS {outil.upper()} ===\n{contenu[:10000]}\n"
        except Exception as e:
            print(f"Erreur lors de la lecture de {fichier}: {e}")
    else:
        print(f"-> Rapport {outil} introuvable (ignoré).")

# 3. Le nouveau Prompt Global
prompt = f"""
Tu es un expert DevSecOps. Voici plusieurs extraits de rapports de sécurité générés par différents outils dans notre pipeline CI/CD. 

Données des rapports :
{contexte_global}

Ta mission :
Fais une synthèse globale, claire et concise (en français) des vulnérabilités trouvées en corrélant les résultats de ces différents outils (SCA, DAST, Secrets, Runtime). 
Organise ta réponse avec des titres clairs (utilise le format Markdown) et mets en évidence les recommandations de sécurité prioritaires à la fin. Ne génère pas de faux positifs si le rapport est vide ou tronqué.

RÈGLE DE FORMATAGE STRICTE : 
Tu dois organiser ta réponse par outil. À la fin de chaque paragraphe concernant un outil, tu DOIS obligatoirement insérer la balise correspondante sur une nouvelle ligne (exactement comme écrit ci-dessous) pour que je puisse y injecter un graphique dynamiquement au dessous de chaque paragraphe :
- À la fin de la section Trivy (SCA), écris : [GRAPHIQUE_SCA]
- À la fin de la section SonarCloud (SAST), écris : [GRAPHIQUE_SAST]
- À la fin de la section ZAP (DAST), écris : [GRAPHIQUE_DAST]
- À la fin de la section Gitleaks (Secrets), écris : [GRAPHIQUE_SECRETS]
- À la fin de la section Falco (Runtime), écris : [GRAPHIQUE_FALCO]

Mets en évidence les recommandations prioritaires à la fin.
"""

print("Envoi des données à Gemini...")
max_tentatives = 3

for tentative in range(max_tentatives):
    try:
        # CORRECTION : Utilisation du modèle 1.5-flash (très stable et rapide)
        response = client.models.generate_content(
            model='gemini-1.5-flash',
            contents=prompt
        )

        # 4. Sauvegarde
        with open('ai-security-summary.txt', 'w', encoding='utf-8') as f:
            f.write(response.text)
        print("Analyse IA terminée et sauvegardée avec succès !")
        break # Succès ! On sort de la boucle de tentatives

    except Exception as e:
        print(f"Erreur API Gemini (Tentative {tentative + 1}/{max_tentatives}) : {e}")
        if tentative < max_tentatives - 1:
            # CORRECTION : On augmente le temps de pause à 20 secondes pour laisser respirer l'API
            print("L'API est surchargée ou la requête est trop lourde. Attente de 20 secondes avant de réessayer...")
            time.sleep(20) 
        else:
            # Si ça échoue 3 fois de suite, on écrit l'erreur dans le rapport
            with open('ai-security-summary.txt', 'w', encoding='utf-8') as f:
                f.write(f"Échec de l'IA après {max_tentatives} tentatives. Serveurs indisponibles.\nErreur: {str(e)}")
