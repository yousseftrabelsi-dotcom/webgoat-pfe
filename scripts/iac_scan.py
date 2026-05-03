"""
scripts/iac_scan.py
──────────────────────────────────────────────────────────────────────────────
Scan IaC (Infrastructure as Code) — Checkov
Analyse les fichiers Dockerfile, YAML (GitHub Actions, K8s, Helm),
Terraform et docker-compose à la recherche de mauvaises configurations.

Prérequis (installé dans le job CI) :
  pip install checkov

Produit :
  checkov-results.json   — rapport complet JSON (uploadé comme artefact)
  checkov-summary.txt    — résumé lisible (affiché dans les logs)
──────────────────────────────────────────────────────────────────────────────
"""

import json
import os
import subprocess
import sys
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

# Répertoire à scanner (racine du dépôt par défaut)
SCAN_DIR         = os.environ.get("SCAN_DIR", ".")
OUTPUT_JSON      = "checkov-results.json"
OUTPUT_SUMMARY   = "checkov-summary.txt"

# Checks à ignorer (faux positifs connus dans WebGoat / CI)
SKIP_CHECKS = [
    "CKV_DOCKER_2",    # Healthcheck — WebGoat n'en expose pas
    "CKV_DOCKER_3",    # User non-root — image de démo
    "CKV2_GHA_1",      # Pinning SHA actions — géré séparément
]

# Seuil de sortie : le script échoue si le nombre de checks critiques > MAX
MAX_CRITICAL = 0
MAX_HIGH     = 10


# ─────────────────────────────────────────────────────────────────────────────
# 1. LANCEMENT DE CHECKOV
# ─────────────────────────────────────────────────────────────────────────────

def run_checkov() -> tuple[int, str, str]:
    """
    Lance Checkov en sous-processus et retourne (returncode, stdout, stderr).
    On utilise --soft-fail pour que Checkov ne bloque pas le script Python
    (on gère nous-mêmes la logique de seuil).
    """
    skip_str = ",".join(SKIP_CHECKS)

    cmd = [
        "checkov",
        "--directory",    SCAN_DIR,
        "--output",       "json",
        "--output-file",  OUTPUT_JSON,
        "--soft-fail",                 # Ne pas exit(1) sur findings
        "--compact",                   # Logs plus lisibles
        "--skip-check",   skip_str,
        # Frameworks ciblés : Dockerfile, GitHub Actions, K8s, docker-compose
        "--framework",    "dockerfile,github_actions,kubernetes,docker_compose",
    ]

    print(f"  Commande : {' '.join(cmd)}\n")

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=SCAN_DIR,
    )
    return result.returncode, result.stdout, result.stderr


# ─────────────────────────────────────────────────────────────────────────────
# 2. PARSEUR DU RÉSULTAT JSON
# ─────────────────────────────────────────────────────────────────────────────

def parse_results(path: str) -> dict:
    """
    Lit checkov-results.json et retourne un dictionnaire de métriques.
    Checkov peut produire soit un objet unique, soit une liste (multi-framework).
    """
    stats = {
        "passed":    0,
        "failed":    0,
        "skipped":   0,
        "critical":  0,
        "high":      0,
        "medium":    0,
        "low":       0,
        "failed_checks": [],   # liste des checks échoués pour le résumé
    }

    if not os.path.isfile(path):
        print(f"[WARN] Fichier de résultats introuvable : {path}", file=sys.stderr)
        return stats

    try:
        with open(path, encoding="utf-8") as fh:
            raw = json.load(fh)
    except Exception as exc:
        print(f"[ERROR] Lecture {path} : {exc}", file=sys.stderr)
        return stats

    # Normalise en liste de rapports (un par framework)
    reports = raw if isinstance(raw, list) else [raw]

    for report in reports:
        summary = report.get("summary", {})
        stats["passed"]  += summary.get("passed",  0)
        stats["failed"]  += summary.get("failed",  0)
        stats["skipped"] += summary.get("skipped", 0)

        results = report.get("results", {})

        for check in results.get("failed_checks", []):
            stats["failed_checks"].append({
                "id":       check.get("check_id",     "—"),
                "name":     check.get("check_name",   "—"),
                "file":     check.get("repo_file_path", check.get("file_path", "—")),
                "severity": check.get("severity",     "UNKNOWN").upper(),
                "resource": check.get("resource",     "—"),
            })
            sev = check.get("severity", "").upper()
            if sev == "CRITICAL":
                stats["critical"] += 1
            elif sev == "HIGH":
                stats["high"]     += 1
            elif sev == "MEDIUM":
                stats["medium"]   += 1
            elif sev == "LOW":
                stats["low"]      += 1

    return stats


# ─────────────────────────────────────────────────────────────────────────────
# 3. GÉNÉRATION DU RÉSUMÉ TEXTE
# ─────────────────────────────────────────────────────────────────────────────

def write_summary(stats: dict, decision: str) -> None:
    run = os.environ.get("GITHUB_RUN_NUMBER", "—")

    lines = [
        "═" * 64,
        "  Checkov IaC Scan — Résumé de sécurité",
        f"  Run : #{run}",
        "═" * 64,
        "",
        f"  ✅  Checks réussis  : {stats['passed']}",
        f"  ❌  Checks échoués  : {stats['failed']}",
        f"  ⏭️   Checks ignorés  : {stats['skipped']}",
        "",
        "  Sévérité des échecs :",
        f"    🔴  CRITICAL : {stats['critical']}",
        f"    🟠  HIGH     : {stats['high']}",
        f"    🟡  MEDIUM   : {stats['medium']}",
        f"    🔵  LOW      : {stats['low']}",
        "",
        "─" * 64,
    ]

    if stats["failed_checks"]:
        lines.append("  Détail des checks échoués :")
        lines.append("")
        for i, chk in enumerate(stats["failed_checks"][:30], 1):   # max 30
            lines.append(
                f"  {i:>2}. [{chk['severity']:<8}] {chk['id']:<20}  {chk['name']}"
            )
            lines.append(f"       Fichier   : {chk['file']}")
            lines.append(f"       Ressource : {chk['resource']}")
            lines.append("")
        if len(stats["failed_checks"]) > 30:
            lines.append(f"  … et {len(stats['failed_checks']) - 30} autres checks. Voir {OUTPUT_JSON}.")
    else:
        lines.append("  Aucun check échoué.")

    lines += [
        "",
        "─" * 64,
        f"  DÉCISION : {decision}",
        "═" * 64,
    ]

    text = "\n".join(lines)
    print(text)

    with open(OUTPUT_SUMMARY, "w", encoding="utf-8") as fh:
        fh.write(text)
    print(f"\n[OK] Résumé sauvegardé → {OUTPUT_SUMMARY}")


# ─────────────────────────────────────────────────────────────────────────────
# 4. MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print("\n" + "═" * 64)
    print("  IaC Security Scan — Checkov")
    print("  Frameworks : Dockerfile · GitHub Actions · K8s · docker-compose")
    print("═" * 64)

    # ── Vérification Checkov installé ────────────────────────────
    chk = subprocess.run(["checkov", "--version"],
                         capture_output=True, text=True)
    if chk.returncode != 0:
        print("[ERROR] Checkov n'est pas installé. Lancez : pip install checkov",
              file=sys.stderr)
        sys.exit(1)
    print(f"  Checkov version : {chk.stdout.strip()}")

    # ── Scan ─────────────────────────────────────────────────────
    print(f"\n[1/3] Scan du répertoire : {os.path.abspath(SCAN_DIR)}")
    rc, stdout, stderr = run_checkov()
    if stdout:
        print(stdout[:2000])   # Affiche les 2000 premiers caractères
    if stderr and rc != 0:
        print(f"[WARN] stderr : {stderr[:500]}", file=sys.stderr)

    # ── Parsing ───────────────────────────────────────────────────
    print(f"\n[2/3] Analyse des résultats ({OUTPUT_JSON})…")
    stats = parse_results(OUTPUT_JSON)

    # ── Décision ──────────────────────────────────────────────────
    print("\n[3/3] Évaluation des seuils…")
    failures = []
    if stats["critical"] > MAX_CRITICAL:
        failures.append(
            f"  🔴 {stats['critical']} checks CRITICAL > seuil ({MAX_CRITICAL})"
        )
    if stats["high"] > MAX_HIGH:
        failures.append(
            f"  🟠 {stats['high']} checks HIGH > seuil ({MAX_HIGH})"
        )

    if failures:
        decision = "❌  SCAN ÉCHOUÉ — seuils de sécurité dépassés"
        for f in failures:
            print(f)
    else:
        decision = "✅  SCAN RÉUSSI — seuils respectés"

    write_summary(stats, decision)

    # ── Sortie pipeline ───────────────────────────────────────────
    # continue-on-error: true est mis dans le YAML, donc on exit(1)
    # uniquement si des seuils critiques sont dépassés.
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
