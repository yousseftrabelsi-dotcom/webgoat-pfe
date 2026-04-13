import os
import google.generativeai as genai

# Configuration Gemini via le secret GitHub
genai.configure(api_key=os.environ.get("GEMINI_API_KEY"))
model = genai.GenerativeModel('gemini-pro')

def run_analysis():
    print("--- DÉBUT DE L'ANALYSE IA ---")
    try:
        prompt = "Donne-moi un conseil de sécurité pour une application Java vulnérable comme WebGoat."
        response = model.generate_content(prompt)
        with open("ai-security-summary.txt", "w") as f:
            f.write("RAPPORT IA PFE :\n")
            f.write(response.text)
        print("Félicitations : L'Agent IA a généré son premier rapport !")
    except Exception as e:
        print(f"Erreur IA : {e}")

if __name__ == "__main__":
    run_analysis()
