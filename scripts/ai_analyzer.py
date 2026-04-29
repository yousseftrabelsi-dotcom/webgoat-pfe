import os
import time
from google import genai

print("Démarrage de l'analyse IA corrélée (tous les outils)...")

client = genai.Client()

# 1. Dictionnaire de tous les rapports attendus du pipeline
fichiers_rapports = {
    "Trivy (SCA - Dépendances)":          "trivy-results.json",
    "Gitleaks (Recherche de Secrets)":     "results.sarif",
    "ZAP (DAST - Analyse Dynamique)":      "report_html.html",
    "Falco (Sécurité Runtime)":            "falco-results.json",
}

contexte_global = ""

# 2. Lecture dynamique de tous les fichiers existants
for outil, fichier in fichiers_rapports.items():
    if os.path.exists(fichier):
        print(f"-> Intégration du rapport : {outil}...")
        try:
            with open(fichier, "r", encoding="utf-8") as f:
                contenu = f.read()
            # CORRECTION : On limite la taille à 15000 caractères pour ne pas surcharger l'API (Erreur 503)
            contexte_global += (
                f"\n\n=== RÉSULTATS {outil.upper()} ===\n{contenu[:15000]}\n"
            )
        except Exception as e:
            print(f"  Erreur lecture {fichier}: {e}")
    else:
        print(f"-> Rapport {outil} introuvable (ignoré).")

if not contexte_global.strip():
    msg = (
        "Aucun rapport de sécurité n'a été trouvé dans le répertoire courant. "
        "Vérifiez que les artefacts ont bien été téléchargés avant ce job."
    )
    print(f"[WARN] {msg}")
    with open("ai-security-summary.txt", "w", encoding="utf-8") as f:
        f.write(msg)
    raise SystemExit(0)

# 3. Prompt avec règle d'injection des balises graphiques
prompt = f"""
Tu es un expert DevSecOps senior. Voici les rapports de sécurité générés par notre pipeline CI/CD
pour le projet WebGoat :

{contexte_global}

Ta mission :
Fais une synthèse globale, claire et concise (en français) en corrélant les résultats de tous
les outils (SCA, DAST, Secrets, Runtime). Utilise le format Markdown avec des titres clairs (##).

RÈGLE DE FORMATAGE STRICTE — À respecter impérativement :
Après chaque section dédiée à un outil, insère la balise correspondante sur une ligne séparée
(exactement comme écrit, sans espace ni modification) :

- Après la section Trivy / SCA      → [GRAPHIQUE_SCA]
- Après la section SonarCloud / SAST → [GRAPHIQUE_SAST]
- Après la section ZAP / DAST       → [GRAPHIQUE_DAST]
- Après la section Gitleaks / Secrets → [GRAPHIQUE_SECRETS]
- Après la section Falco / Runtime  → [GRAPHIQUE_FALCO]

Termine toujours par une section ## Recommandations Prioritaires listant les actions urgentes.
"""

print("Envoi des données à Gemini...")

# 4. CORRECTION : Logique de Retry pour éviter l'échec direct en cas d'erreur 503
max_retries = 3

for tentative in range(max_retries):
    try:
        print(f"Tentative {tentative + 1}/{max_retries}...")
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
        )
        # Si on arrive ici, l'API a répondu avec succès
        with open("ai-security-summary.txt", "w", encoding="utf-8") as f:
            f.write(response.text)
        print("Analyse IA terminée et sauvegardée avec succès !")
        break # On sort de la boucle puisque ça a marché

    except Exception as e:
        erreur_msg = str(e)
        print(f"Erreur API interceptée : {erreur_msg}")
        
        # On vérifie si l'erreur est due à une surcharge (503, 500, ou quotas)
        if "503" in erreur_msg or "500" in erreur_msg or "Resource exhausted" in erreur_msg:
            if tentative < max_retries - 1:
                print("Le serveur Gemini est surchargé. Pause de 15 secondes avant de réessayer...")
                time.sleep(15)
            else:
                print("Toutes les tentatives ont échoué.")
                with open("ai-security-summary.txt", "w", encoding="utf-8") as f:
                    f.write("Erreur : Impossible de générer l'analyse IA. Les serveurs de Google Gemini sont indisponibles (Erreur 503 continue).")
        else:
            # Si c'est une autre erreur (clé API invalide, etc.), on arrête tout de suite
            with open("ai-security-summary.txt", "w", encoding="utf-8") as f:
                f.write(f"Erreur lors de la génération de l'analyse IA : {erreur_msg}")
            break
