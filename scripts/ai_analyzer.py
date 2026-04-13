import os
import google.generativeai as genai

# Configuration de l'IA avec ta clé secrète
genai.configure(api_key=os.environ.get("GEMINI_API_KEY"))
model = genai.GenerativeModel('gemini-pro')

def run_analysis():
    print("Démarrage de l'analyse IA...")
    
    # On vérifie si le rapport Trivy existe
    report_exists = os.path.exists("trivy-results.json")
    
    context = "Le scan Trivy a réussi." if report_exists else "Le scan Trivy a échoué (problème d'image Docker)."
    
    prompt = f"""
    En tant qu'expert DevSecOps pour mon PFE, analyse cette situation : {context}.
    Donne-moi 3 recommandations de sécurité pour une application Java comme WebGoat.
    Réponds en français et sois concis.
    """
    
    try:
        response = model.generate_content(prompt)
        with open("ai-security-summary.txt", "w", encoding="utf-8") as f:
            f.write("=== RAPPORT DE L'AGENT IA (PFE YOUSSEF) ===\n")
            f.write(response.text)
        print("Rapport IA généré avec succès dans ai-security-summary.txt")
    except Exception as e:
        print(f"Erreur avec Gemini : {e}")

if __name__ == "__main__":
    run_analysis()
