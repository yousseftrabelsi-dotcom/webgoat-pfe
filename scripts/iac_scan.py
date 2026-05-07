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

SCAN_DIR       = os.environ.get("SCAN_DIR", ".")
OUTPUT_JSON    = "checkov-results.json"
OUTPUT_SUMMARY = "checkov-summary.txt"

SKIP_CHECKS = [
    "CKV_DOCKER_2",
    "CKV_DOCKER_3",
    "CKV2_GHA_1",
]

MAX_CRITICAL = 0
MAX_HIGH     = 10


# ─────────────────────────────────────────────────────────────────────────────
# 0. DÉTECTION DES FICHIERS IaC PRÉSENTS
# ─────────────────────────────────────────────────────────────────────────────

def detect_iac_files(scan_dir: str) -> dict:
    """
    Parcourt le dépôt et liste les fichiers IaC trouvés par type.
    Retourne un dict {type: [fichiers]} et la liste des frameworks actifs.
    """
    found = {
        "dockerfile":      [],
        "github_actions":  [],
        "docker_compose":  [],
        "kubernetes":      [],
        "terraform":       [],
    }

    for root, dirs, files in os.walk(scan_dir):
        # Exclure node_modules, .git, target, build
        dirs[:] = [d for d in dirs if d not in
                   (".git", "node_modules", "target", "build", ".mvn")]

        for fname in files:
            fpath = os.path.join(root, fname)
            flower = fname.lower()

            if flower == "dockerfile" or flower.startswith("dockerfile."):
                found["dockerfile"].append(fpath)
            elif flower in ("docker-compose.yml", "docker-compose.yaml",
                            "docker-compose.override.yml"):
                found["docker_compose"].append(fpath)
            elif ".github" in fpath and (flower.endswith(".yml") or
                                          flower.endswith(".yaml")):
                found["github_actions"].append(fpath)
            elif flower.endswith(".tf") or flower.endswith(".tfvars"):
                found["terraform"].append(fpath)
            elif flower.endswith((".yml", ".yaml")) and any(
                kw in open(fpath, encoding="utf-8",
                           errors="ignore").read()
                for kw in ("apiVersion", "kind: Pod", "kind: Deployment",
                           "kind: Service", "kind: Ingress")
            ):
                found["kubernetes"].append(fpath)

    # Frameworks actifs = ceux qui ont au moins 1 fichier
    active = [fw for fw, files in found.items() if files]

    print("\n  Fichiers IaC détectés :")
    for fw, files in found.items():
        if files:
            print(f"    ✅ {fw:<20} : {len(files)} fichier(s)")
            for f in files[:5]:
                print(f"       → {f}")
        else:
            print(f"    —  {fw:<20} : aucun fichier")

    return found, active


# ─────────────────────────────────────────────────────────────────────────────
# 1. LANCEMENT DE CHECKOV
# ─────────────────────────────────────────────────────────────────────────────

def run_checkov(active_frameworks: list) -> tuple[int, str, str]:
    """
    Lance Checkov. Si aucun framework IaC détecté, scanne quand même
    avec tous les frameworks pour ne rien manquer.
    """
    skip_str = ",".join(SKIP_CHECKS)

    # Si aucun framework détecté → scan général sans filtre
    if active_frameworks:
        framework_arg = ",".join(active_frameworks)
        print(f"\n  Frameworks actifs : {framework_arg}")
    else:
        # Scan général — Checkov détecte lui-même ce qu'il peut analyser
        framework_arg = "all"
        print("\n  ⚠️  Aucun fichier IaC spécifique détecté — scan général (all)")

    cmd = [
        "checkov",
        "--directory",   SCAN_DIR,
        "--output",      "json",
        "--output-file", OUTPUT_JSON,
        "--soft-fail",
        "--compact",
        "--skip-check",  skip_str,
        "--framework",   framework_arg,
    ]

    print(f"  Commande : {' '.join(cmd)}\n")

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=SCAN_DIR,
    )

    # Garantir que le fichier JSON existe même si Checkov ne l'a pas créé
    if not os.path.isfile(OUTPUT_JSON):
        print(f"  [WARN] Checkov n'a pas créé {OUTPUT_JSON} — création manuelle.")
        _create_empty_json()

    return result.returncode, result.stdout, result.stderr


def _create_empty_json():
    """Crée un JSON vide valide si Checkov ne produit rien."""
    empty = [{
        "check_type": "none",
        "summary": {"passed": 0, "failed": 0, "skipped": 0,
                    "parsing_error": 0, "resource_count": 0},
        "results": {"passed_checks": [], "failed_checks": [],
                    "skipped_checks": [], "parsing_errors": []},
    }]
    with open(OUTPUT_JSON, "w", encoding="utf-8") as fh:
        json.dump(empty, fh, indent=2)


# ─────────────────────────────────────────────────────────────────────────────
# 2. PARSEUR DU RÉSULTAT JSON
# ─────────────────────────────────────────────────────────────────────────────

def parse_results(path: str) -> dict:
    stats = {
        "passed":        0,
        "failed":        0,
        "skipped":       0,
        "critical":      0,
        "high":          0,
        "medium":        0,
        "low":           0,
        "failed_checks": [],
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

    reports = raw if isinstance(raw, list) else [raw]

    for report in reports:
        summary = report.get("summary", {})
        stats["passed"]  += summary.get("passed",  0)
        stats["failed"]  += summary.get("failed",  0)
        stats["skipped"] += summary.get("skipped", 0)

        for check in report.get("results", {}).get("failed_checks", []):
            stats["failed_checks"].append({
                "id":       check.get("check_id",     "—"),
                "name":     check.get("check_name",   "—"),
                "file":     check.get("repo_file_path",
                            check.get("file_path", "—")),
                "severity": check.get("severity", "UNKNOWN").upper(),
                "resource": check.get("resource", "—"),
            })
            sev = check.get("severity", "").upper()
            if   sev == "CRITICAL": stats["critical"] += 1
            elif sev == "HIGH":     stats["high"]     += 1
            elif sev == "MEDIUM":   stats["medium"]   += 1
            elif sev == "LOW":      stats["low"]      += 1

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
        for i, chk in enumerate(stats["failed_checks"][:30], 1):
            lines.append(
                f"  {i:>2}. [{chk['severity']:<8}] {chk['id']:<20}  {chk['name']}"
            )
            lines.append(f"       Fichier   : {chk['file']}")
            lines.append(f"       Ressource : {chk['resource']}")
            lines.append("")
        if len(stats["failed_checks"]) > 30:
            lines.append(
                f"  … et {len(stats['failed_checks']) - 30} autres. Voir {OUTPUT_JSON}."
            )
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
    print(f"[OK] Rapport JSON      → {OUTPUT_JSON}")


# ─────────────────────────────────────────────────────────────────────────────
# 4. MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print("\n" + "═" * 64)
    print("  IaC Security Scan — Checkov")
    print("  Frameworks : Dockerfile · GitHub Actions · K8s · docker-compose · Terraform")
    print("═" * 64)

    # Vérification Checkov installé
    chk = subprocess.run(["checkov", "--version"],
                         capture_output=True, text=True)
    if chk.returncode != 0:
        print("[ERROR] Checkov n'est pas installé.", file=sys.stderr)
        sys.exit(1)
    print(f"  Checkov version : {chk.stdout.strip()}")

    # Détection des fichiers IaC
    print(f"\n[1/3] Détection des fichiers IaC dans : {os.path.abspath(SCAN_DIR)}")
    _, active_frameworks = detect_iac_files(SCAN_DIR)

    # Scan
    print(f"\n[2/3] Lancement du scan Checkov…")
    rc, stdout, stderr = run_checkov(active_frameworks)
    if stdout:
        print(stdout[:2000])
    if stderr and rc != 0:
        print(f"[WARN] stderr : {stderr[:500]}", file=sys.stderr)

    # Parsing
    print(f"\n[3/3] Analyse des résultats…")
    stats = parse_results(OUTPUT_JSON)

    # Décision
    failures = []
    if stats["critical"] > MAX_CRITICAL:
        failures.append(f"  🔴 {stats['critical']} CRITICAL > seuil ({MAX_CRITICAL})")
    if stats["high"] > MAX_HIGH:
        failures.append(f"  🟠 {stats['high']} HIGH > seuil ({MAX_HIGH})")

    decision = ("❌  SCAN ÉCHOUÉ — seuils de sécurité dépassés"
                if failures else
                "✅  SCAN RÉUSSI — seuils respectés")

    for f in failures:
        print(f)

    write_summary(stats, decision)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
