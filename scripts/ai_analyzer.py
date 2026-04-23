import os
from google import genai

print("Démarrage de l'analyse IA corrélée (tous les outils)...")


def find_report_path(filename: str) -> str | None:
    if os.path.isfile(filename):
        return filename
    for root, _, files in os.walk("."):
        if filename in files:
            return os.path.join(root, filename)
    return None


def ensure_graph_tags(text: str) -> str:
    required_tags = [
        "[GRAPHIQUE_SCA]",
        "[GRAPHIQUE_SAST]",
        "[GRAPHIQUE_DAST]",
        "[GRAPHIQUE_SECRETS]",
        "[GRAPHIQUE_FALCO]",
    ]
    missing = [tag for tag in required_tags if tag not in text]
    if not missing:
        return text

    text = text.rstrip() + "\n\n## Visualisations associées\n"
    for tag in missing:
        text += f"\n{tag}\n"
    return text


api_key = os.environ.get("GEMINI_API_KEY")
if not api_key:
    msg = (
        "## Analyse IA indisponible\n"
        "La variable GEMINI_API_KEY est absente."
        "\n\n[GRAPHIQUE_SCA]\n\n[GRAPHIQUE_SAST]\n\n[GRAPHIQUE_DAST]"
        "\n\n[GRAPHIQUE_SECRETS]\n\n[GRAPHIQUE_FALCO]"
    )
    with open("ai-security-summary.txt", "w", encoding="utf-8") as f:
        f.write(msg)
    print("[WARN] GEMINI_API_KEY absente — fichier fallback généré.")
    raise SystemExit(0)

client = genai.Client(api_key=api_key)

# Dictionnaire des rapports attendus du pipeline
fichiers_rapports = {
    "Trivy (SCA - Dépendances)": "trivy-results.json",
    "SonarCloud (SAST - Code)": "sonar-results.json",
    "Gitleaks (Recherche de Secrets)": "results.sarif",
    "ZAP (DAST - Analyse Dynamique)": "report_html.html",
    "Falco (Sécurité Runtime)": "falco-results.json",
}

contexte_global = ""
for outil, fichier in fichiers_rapports.items():
    located = find_report_path(fichier)
    if located:
        print(f"-> Intégration du rapport : {outil} ({located})...")
        try:
            with open(located, "r", encoding="utf-8", errors="ignore") as f:
                contenu = f.read()
            contexte_global += f"\n\n=== RÉSULTATS {outil.upper()} ===\n{contenu[:30000]}\n"
        except Exception as e:
            print(f"  Erreur lecture {located}: {e}")
    else:
        print(f"-> Rapport {outil} introuvable (ignoré).")

if not contexte_global.strip():
    msg = (
        "## Aucun rapport exploitable\n"
        "Aucun rapport de sécurité n'a été trouvé dans le répertoire courant ou ses sous-dossiers."
        " Vérifiez que les artefacts ont bien été téléchargés avant ce job."
        "\n\n[GRAPHIQUE_SCA]\n\n[GRAPHIQUE_SAST]\n\n[GRAPHIQUE_DAST]"
        "\n\n[GRAPHIQUE_SECRETS]\n\n[GRAPHIQUE_FALCO]"
    )
    print(f"[WARN] {msg}")
    with open("ai-security-summary.txt", "w", encoding="utf-8") as f:
        f.write(msg)
    raise SystemExit(0)

prompt = f"""
Tu es un expert DevSecOps senior.
Voici les rapports de sécurité générés par notre pipeline CI/CD pour le projet WebGoat :

{contexte_global}

Ta mission :
1. Produis une synthèse globale claire, concise et professionnelle en français.
2. Corrèle les résultats SCA, SAST, DAST, Secrets et Runtime.
3. Pour chaque section, indique brièvement : le constat, l'impact, puis l'action recommandée.
4. Si une source manque, précise explicitement que les données sont indisponibles.
5. Termine par une section ## Recommandations Prioritaires avec les actions les plus urgentes.

Format obligatoire :
- ## Dépendances (Trivy)
- ## Code Statique (SonarCloud)
- ## Attaques Web (ZAP)
- ## Secrets Git (Gitleaks)
- ## Runtime (Falco)
- ## Recommandations Prioritaires

RÈGLE DE FORMATAGE STRICTE :
Insère exactement la balise demandée sur sa propre ligne à la fin de chaque section :
- Après Dépendances (Trivy)       => [GRAPHIQUE_SCA]
- Après Code Statique (SonarCloud) => [GRAPHIQUE_SAST]
- Après Attaques Web (ZAP)         => [GRAPHIQUE_DAST]
- Après Secrets Git (Gitleaks)     => [GRAPHIQUE_SECRETS]
- Après Runtime (Falco)            => [GRAPHIQUE_FALCO]
"""

print("Envoi des données à Gemini...")
try:
    response = client.models.generate_content(
        model="gemini-2.5-flash",
        contents=prompt,
    )
    text = response.text if getattr(response, "text", None) else "## Analyse IA indisponible"
    text = ensure_graph_tags(text)
    with open("ai-security-summary.txt", "w", encoding="utf-8") as f:
        f.write(text)
    print("Analyse IA terminée et sauvegardée avec succès !")
except Exception as e:
    print(f"Erreur lors de l'appel à l'API Gemini : {e}")
    fallback = (
        "## Erreur lors de la génération IA\n"
        f"{e}"
        "\n\n[GRAPHIQUE_SCA]\n\n[GRAPHIQUE_SAST]\n\n[GRAPHIQUE_DAST]"
        "\n\n[GRAPHIQUE_SECRETS]\n\n[GRAPHIQUE_FALCO]"
    )
    with open("ai-security-summary.txt", "w", encoding="utf-8") as f:
        f.write(fallback)
