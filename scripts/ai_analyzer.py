import os
from google import genai

print("Démarrage de l'analyse IA...")

# 1. Initialisation du nouveau client (il va chercher GEMINI_API_KEY tout seul)
client = genai.Client()

# 2. Lecture du rapport Trivy généré par le pipeline
with open('trivy-results.json', 'r') as fichier:
    rapport = fichier.read()

# 3. Appel à Gemini avec la nouvelle syntaxe
response = client.models.generate_content(
    model='gemini-1.5-flash',
    contents="Tu es un expert DevSecOps. Fais un résumé clair et concis (en français) des vulnérabilités trouvées dans ce rapport Trivy : " + rapport
)

# 4. Sauvegarde du résultat dans le fichier final
with open('ai-security-summary.txt', 'w', encoding='utf-8') as f:
    f.write(response.text)

print("Analyse terminée avec succès !")
