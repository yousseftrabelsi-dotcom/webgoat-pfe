import os
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
                # On limite volontairement la taille (ex: HTML ZAP trop lourd)
                contexte_global += f"\n\n=== RÉSULTATS {outil.upper()} ===\n{contenu[:60000]}\n"
        except Exception as e:
            print(f"Erreur lors de la lecture de {fichier}: {e}")
    else:
        print(f"-> Rapport {outil} introuvable (ignoré).")

# 3. Le nouveau Prompt Global
prompt = f"""
Tu es un expert DevSecOps. Voici plusieurs rapports de sécurité générés par différents outils dans notre pipeline CI/CD. 

Données des rapports :
{contexte_global}

Ta mission :
Fais une synthèse globale, claire et concise (en français) des vulnérabilités trouvées en corrélant les résultats de ces différents outils (SCA, DAST, Secrets, Runtime). 
Organise ta réponse avec des titres clairs (utilise le format Markdown) et mets en évidence les recommandations de sécurité prioritaires à la fin.
"""

import time # N'oublie pas d'ajouter ça tout en haut de ton fichier avec les autres imports si ce n'est pas fait !

print("Envoi des données à Gemini...")
max_tentatives = 3

for tentative in range(max_tentatives):
    try:
        response = client.models.generate_content(
            model='gemini-2.5-flash',
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
            print("L'API est surchargée. Attente de 15 secondes avant de réessayer...")
            time.sleep(15) # Attendre 15s avant de refaire un appel
        else:
            # Si ça échoue 3 fois de suite, on écrit l'erreur dans le rapport
            with open('ai-security-summary.txt', 'w', encoding='utf-8') as f:
                f.write(f"Échec de l'IA après {max_tentatives} tentatives. Serveurs indisponibles.\nErreur: {str(e)}")
