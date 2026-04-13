import os
import json
import google.generativeai as genai

# Configuration Gemini
genai.configure(api_key=os.environ["GEMINI_API_KEY"])
model = genai.GenerativeModel('gemini-pro')

def run_analysis():
    print("Analyse des vulnérabilités par l'Agent IA...")
    # Simulation de lecture du rapport Trivy
    prompt = "En tant qu'expert DevSecOps, donne-moi un conseil de sécurité rapide pour WebGoat."
    response = model.generate_content(prompt)
    
    with open("ai-security-summary.txt", "w") as f:
        f.write(response.text)
    print("Rapport IA généré avec succès.")

if __name__ == "__main__":
    run_analysis()
