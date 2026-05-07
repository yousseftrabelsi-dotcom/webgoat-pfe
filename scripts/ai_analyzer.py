"""
scripts/ai_analyzer.py
──────────────────────────────────────────────────────────────────────────────
Analyse IA corrélée — Pipeline DevSecOps WebGoat
Agrège les rapports SCA · SAST · DAST · Secrets · Runtime · IaC et génère
une synthèse Markdown enrichie via Gemini.
──────────────────────────────────────────────────────────────────────────────
"""

import os
import re
import sys
import time

from google import genai

# ─────────────────────────────────────────────────────────────────────────────
# 1. CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

OUTPUT_FILE  = "ai-security-summary.txt"
MAX_CHARS    = 12_000
MAX_RETRIES  = 5
RETRY_DELAY  = 30
GEMINI_MODEL = "gemini-2.0-flash"   # 2.0-flash : plus stable que 2.5-flash

# Rapports à intégrer — IaC Checkov ajouté
REPORTS = {
    "Trivy / SCA — Dépendances":       "trivy-results.json",
    "SonarCloud / SAST — Code source": "sonar-results.json",
    "OWASP ZAP / DAST — Web":          "report_html.html",
    "Gitleaks / Secrets":              "results.sarif",
    "Falco / Runtime":                 "falco-results.json",
    "Checkov / IaC — Infrastructure":  "checkov-results.json",   # ← NOUVEAU
}


# ─────────────────────────────────────────────────────────────────────────────
# 2. HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _write_output(text: str) -> None:
    with open(OUTPUT_FILE, "w", encoding="utf-8") as fh:
        fh.write(text)


def _extract_sonar_kpis(path: str) -> str:
    import json
    try:
        with open(path, encoding="utf-8") as fh:
            raw = json.load(fh)
        measures = raw.get("component", {}).get("measures", [])
        kpis = {m["metric"]: m.get("value", "N/A") for m in measures}
        lines = ["Métriques SonarCloud extraites :"]
        mapping = {
            "bugs":                     "🐛  Bugs",
            "vulnerabilities":          "🔓  Vulnérabilités",
            "security_hotspots":        "🔥  Hotspots de sécurité",
            "code_smells":              "🧹  Code smells",
            "coverage":                 "🧪  Couverture de tests (%)",
            "duplicated_lines_density": "📋  Duplication (%)",
            "sqale_rating":             "📐  Note maintenabilité (A-E)",
            "reliability_rating":       "🛡️  Note fiabilité (A-E)",
            "security_rating":          "🔒  Note sécurité (A-E)",
        }
        for metric, label in mapping.items():
            if metric in kpis:
                lines.append(f"  {label} : {kpis[metric]}")
        return "\n".join(lines) if len(lines) > 1 else ""
    except Exception as exc:
        print(f"  [WARN] Lecture SonarCloud : {exc}", file=sys.stderr)
        return ""


def _extract_checkov_kpis(path: str) -> str:
    """
    Extrait un résumé lisible du rapport Checkov JSON.
    Évite d'envoyer tout le JSON brut à Gemini.
    """
    import json
    try:
        with open(path, encoding="utf-8") as fh:
            raw = json.load(fh)

        reports = raw if isinstance(raw, list) else [raw]
        total_passed = 0
        total_failed = 0
        severities   = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        failed_checks = []

        for report in reports:
            summary = report.get("summary", {})
            total_passed += summary.get("passed", 0)
            total_failed += summary.get("failed", 0)

            for chk in report.get("results", {}).get("failed_checks", []):
                sev = chk.get("severity", "LOW").upper()
                if sev in severities:
                    severities[sev] += 1
                else:
                    severities["LOW"] += 1

                # Garde les 10 premiers checks échoués pour contexte IA
                if len(failed_checks) < 10:
                    failed_checks.append({
                        "id":       chk.get("check_id", "—"),
                        "name":     chk.get("check", {}).get("name", chk.get("check_id", "—")),
                        "severity": sev,
                        "file":     chk.get("repo_file_path", chk.get("file_path", "—")),
                        "resource": chk.get("resource", "—"),
                    })

        lines = [
            "Résumé Checkov IaC :",
            f"  ✅ Checks passés   : {total_passed}",
            f"  ❌ Checks échoués  : {total_failed}",
            f"  🔴 CRITICAL        : {severities['CRITICAL']}",
            f"  🟠 HIGH            : {severities['HIGH']}",
            f"  🟡 MEDIUM          : {severities['MEDIUM']}",
            f"  🟢 LOW             : {severities['LOW']}",
        ]

        if failed_checks:
            lines.append("\n  Principaux checks échoués :")
            for c in failed_checks:
                lines.append(
                    f"    [{c['severity']}] {c['id']} — {c['name']} "
                    f"(fichier: {c['file']}, ressource: {c['resource']})"
                )

        return "\n".join(lines)

    except Exception as exc:
        print(f"  [WARN] Lecture Checkov : {exc}", file=sys.stderr)
        return ""


# ─────────────────────────────────────────────────────────────────────────────
# 3. CONSTRUCTION DU CONTEXTE
# ─────────────────────────────────────────────────────────────────────────────

def build_context() -> str:
    context_parts = []

    for label, filepath in REPORTS.items():
        if not os.path.exists(filepath):
            print(f"  [SKIP] {label} — fichier introuvable ({filepath})")
            continue

        print(f"  [OK]   Intégration : {label}")

        # Traitement spécifique SonarCloud
        if "sonar" in filepath.lower():
            sonar_text = _extract_sonar_kpis(filepath)
            if sonar_text:
                context_parts.append(
                    f"\n\n=== RÉSULTATS {label.upper()} ===\n{sonar_text}\n"
                )
                continue

        # Traitement spécifique Checkov  ← NOUVEAU
        if "checkov" in filepath.lower():
            checkov_text = _extract_checkov_kpis(filepath)
            if checkov_text:
                context_parts.append(
                    f"\n\n=== RÉSULTATS {label.upper()} ===\n{checkov_text}\n"
                )
                continue

        try:
            with open(filepath, encoding="utf-8") as fh:
                content = fh.read()
            context_parts.append(
                f"\n\n=== RÉSULTATS {label.upper()} ===\n{content[:MAX_CHARS]}\n"
            )
        except Exception as exc:
            print(f"  [ERROR] Lecture {filepath} : {exc}", file=sys.stderr)

    return "".join(context_parts)


# ─────────────────────────────────────────────────────────────────────────────
# 4. PROMPT — Section IaC ajoutée
# ─────────────────────────────────────────────────────────────────────────────

PROMPT_TEMPLATE = """
Tu es un expert DevSecOps senior. Voici les rapports de sécurité complets générés par le
pipeline CI/CD du projet WebGoat :

{context}

════════════════════════════════════════════════════════════════
MISSION
════════════════════════════════════════════════════════════════
Rédige une synthèse globale en français, claire et structurée, en corrélant
les résultats de tous les outils (SCA, SAST, DAST, Secrets, Runtime, IaC).
Utilise le format Markdown avec des titres de niveau ## pour chaque section.

════════════════════════════════════════════════════════════════
STRUCTURE OBLIGATOIRE DU RAPPORT
════════════════════════════════════════════════════════════════

## 1. Vue d'ensemble
Résumé exécutif en 3-5 phrases : niveau de risque global, points critiques, tendance générale.

## 2. Analyse SCA — Dépendances (Trivy)
Commente les vulnérabilités détectées dans les dépendances tierces.
Mentionne les CVE critiques/élevées si présentes.
[GRAPHIQUE_SCA]

## 3. Analyse SAST — Code Source (SonarCloud)
Analyse les bugs, vulnérabilités et hotspots remontés par SonarCloud.
Corrèle avec les vulnérabilités SCA si des patterns communs existent.
[GRAPHIQUE_SAST]

## 4. Analyse DAST — Sécurité Web (OWASP ZAP)
Détail des alertes web (injections, CORS, CSRF, sessions, authentification…).
[GRAPHIQUE_DAST]

## 5. Analyse Secrets — Gitleaks
Présence ou absence de secrets en clair dans le code source.
Évalue l'impact si des secrets ont été détectés.
[GRAPHIQUE_SECRETS]

## 6. Analyse Runtime — Comportements (Falco)
Commente les événements suspects capturés pendant l'exécution.
[GRAPHIQUE_FALCO]

## 7. Analyse IaC — Infrastructure (Checkov)
Analyse les misconfigurations détectées dans les fichiers Dockerfile, docker-compose, IaC.
Identifie les checks critiques et élevés échoués.
Corrèle avec les vulnérabilités OWASP correspondantes (A05, A02, A04...).
[GRAPHIQUE_IAC]

## 8. Corrélations inter-outils
Identifie les vulnérabilités ou risques qui apparaissent dans plusieurs outils à la fois
(ex. une CVE Trivy exploitable via ZAP, un secret corrélé à un accès Falco suspect,
une misconfiguration IaC Checkov liée à une alerte Runtime Falco).

## 9. Recommandations Prioritaires
Liste numérotée des actions urgentes, classées par criticité décroissante.
Pour chaque action : outil concerné, impact attendu, effort estimé (Faible/Moyen/Élevé).

════════════════════════════════════════════════════════════════
RÈGLES DE FORMATAGE STRICTES
════════════════════════════════════════════════════════════════
- Les balises [GRAPHIQUE_*] doivent apparaître EXACTEMENT comme indiqué ci-dessus,
  sur une ligne seule, sans espace ni modification.
- Chaque section ## doit être présente même si les données sont absentes
  (écrire "Aucune donnée disponible pour cet outil." dans ce cas).
- Pas de titre de niveau # (h1) dans le rapport.
- Langage professionnel, concis, orienté action.
"""


# ─────────────────────────────────────────────────────────────────────────────
# 5. APPEL API AVEC RETRY
# ─────────────────────────────────────────────────────────────────────────────

def call_gemini(prompt: str) -> str | None:
    client = genai.Client()

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            print(f"  Tentative {attempt}/{MAX_RETRIES}...")
            response = client.models.generate_content(
                model=GEMINI_MODEL,
                contents=prompt,
            )
            return response.text

        except Exception as exc:
            msg = str(exc)
            print(f"  [ERROR] Tentative {attempt} échouée : {msg}", file=sys.stderr)

            is_retryable = any(code in msg for code in ("503", "500", "Resource exhausted", "overloaded"))

            if is_retryable and attempt < MAX_RETRIES:
                print(f"  Pause {RETRY_DELAY}s avant nouvel essai…", file=sys.stderr)
                time.sleep(RETRY_DELAY)
            elif not is_retryable:
                print("  Erreur non-récupérable, abandon.", file=sys.stderr)
                return None

    return None


# ─────────────────────────────────────────────────────────────────────────────
# 6. POINT D'ENTRÉE
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    print("\n" + "═" * 60)
    print("  Analyse IA corrélée — Pipeline DevSecOps WebGoat")
    print("═" * 60)

    print("\n[1/3] Lecture des rapports disponibles…")
    context = build_context()

    if not context.strip():
        fallback = (
            "Aucun rapport de sécurité trouvé dans le répertoire courant.\n"
            "Vérifiez que les artefacts ont été téléchargés avant ce job."
        )
        print(f"\n[WARN] {fallback}")
        _write_output(fallback)
        sys.exit(0)

    print("\n[2/3] Envoi à Gemini pour analyse…")
    prompt = PROMPT_TEMPLATE.format(context=context)
    result = call_gemini(prompt)

    if result is None:
        error_msg = (
            "Erreur : Impossible de générer l'analyse IA.\n"
            "Les serveurs Gemini sont indisponibles ou la clé API est invalide.\n"
            "Consultez les logs du job ai-agent-analysis pour plus de détails."
        )
        _write_output(error_msg)
        print(f"\n[FAIL] {error_msg}", file=sys.stderr)
        sys.exit(1)

    print("\n[3/3] Sauvegarde du rapport IA…")
    _write_output(result)

    lines = result.count("\n")
    chars = len(result)
    print(f"\n[OK]  Rapport IA généré → {OUTPUT_FILE}  ({lines} lignes, {chars} caractères)")
    print("═" * 60 + "\n")


if __name__ == "__main__":
    main()
