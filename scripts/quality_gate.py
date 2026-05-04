"""
scripts/quality_gate.py
──────────────────────────────────────────────────────────────────────────────
Quality Gate DevSecOps — Bloque le pipeline si les seuils de risque sont
dépassés. Lit les rapports du pipeline et produit un rapport de décision.

Codes de sortie :
  0 → PASS   (déploiement autorisé)
  1 → FAIL   (déploiement bloqué)
──────────────────────────────────────────────────────────────────────────────
"""

import json
import os
import sys
from datetime import datetime, timezone

# ─────────────────────────────────────────────────────────────────────────────
# SEUILS — modifier selon la politique de sécurité du projet
# ─────────────────────────────────────────────────────────────────────────────

THRESHOLDS = {
    # Secrets : zéro tolérance absolue
    "secrets_max":          0,

    # Trivy SCA
    "trivy_critical_max":   5,    # tolérance pour CVE critiques (bibliothèques legacy)
    "trivy_high_max":       30,   # max 30 CVE élevées (WebGoat est intentionnellement vulnérable)

    # SonarCloud SAST
    "sonar_vulnerabilities_max": 50,
    "sonar_hotspots_max":        80,

    # OWASP ZAP DAST
    "zap_high_max":         5,    # max 5 alertes hautes

    # Falco Runtime
    "falco_critical_max":   0,
    "falco_error_max":      5,

    # Score global
    "risk_score_max":       85,   # seuil relevé pour refléter la nature de WebGoat
}

OUTPUT_FILE = "quality-gate-report.txt"


# ─────────────────────────────────────────────────────────────────────────────
# PARSEURS (versions légères, sans dépendances externes)
# ─────────────────────────────────────────────────────────────────────────────

def _load_json(path: str) -> dict | list | None:
    if not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def get_gitleaks_count() -> int:
    for path in ("results.sarif", "gitleaks-report.json"):
        data = _load_json(path)
        if data is None:
            continue
        if isinstance(data, list):
            return len(data)
        if isinstance(data, dict) and "runs" in data:
            return len(data["runs"][0].get("results", []))
    return 0


def get_trivy_counts() -> dict:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    data = _load_json("trivy-results.json")
    if not data:
        return counts
    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            sev = vuln.get("Severity", "").capitalize()
            if sev in counts:
                counts[sev] += 1
    return counts


def get_sonar_counts() -> dict:
    defaults = {"vulnerabilities": 0, "security_hotspots": 0, "bugs": 0}
    data = _load_json("sonar-results.json")
    if not data:
        return defaults
    for m in data.get("component", {}).get("measures", []):
        metric = m.get("metric")
        if metric in defaults:
            defaults[metric] = int(m.get("value", 0))
    return defaults


def get_zap_counts() -> dict:
    counts = {"High": 0, "Medium": 0, "Low": 0}
    data = _load_json("report_json.json")
    if not data:
        return counts
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            risk = alert.get("riskdesc", "").split(" ")[0]
            if risk in counts:
                counts[risk] += 1
    return counts


def get_falco_counts() -> dict:
    counts = {"Notice": 0, "Warning": 0, "Error": 0, "Critical": 0}
    if not os.path.isfile("falco-results.json"):
        return counts
    try:
        with open("falco-results.json", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    log = json.loads(line)
                    prio = log.get("priority", "").capitalize()
                    if prio in counts:
                        counts[prio] += 1
                except json.JSONDecodeError:
                    pass
    except Exception:
        pass
    return counts


def compute_score(trivy, falco, secrets, zap) -> int:
    if secrets > 0:
        return 100
    raw = (
        trivy.get("Critical", 0) * 8
        + trivy.get("High", 0)   * 3
        + (falco.get("Error", 0) + falco.get("Critical", 0)) * 10
        + zap.get("High", 0)     * 5
    )
    return min(100, raw)


# ─────────────────────────────────────────────────────────────────────────────
# ÉVALUATION DES SEUILS
# ─────────────────────────────────────────────────────────────────────────────

def evaluate(label: str, value: int, max_allowed: int) -> dict:
    passed = value <= max_allowed
    return {
        "label":       label,
        "value":       value,
        "max_allowed": max_allowed,
        "passed":      passed,
        "symbol":      "✅ PASS" if passed else "❌ FAIL",
    }


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print("\n" + "═" * 60)
    print("  Quality Gate — DevSecOps WebGoat Pipeline")
    print("═" * 60)

    # Collecte des métriques
    secrets  = get_gitleaks_count()
    trivy    = get_trivy_counts()
    sonar    = get_sonar_counts()
    zap      = get_zap_counts()
    falco    = get_falco_counts()
    score    = compute_score(trivy, falco, secrets, zap)

    T = THRESHOLDS

    checks = [
        evaluate("🔑 Secrets détectés",           secrets,                    T["secrets_max"]),
        evaluate("💣 CVE Critiques (Trivy)",       trivy["Critical"],          T["trivy_critical_max"]),
        evaluate("🔶 CVE Élevées (Trivy)",         trivy["High"],              T["trivy_high_max"]),
        evaluate("🐛 Vulnérabilités SAST (Sonar)", sonar["vulnerabilities"],   T["sonar_vulnerabilities_max"]),
        evaluate("🔥 Hotspots SAST (Sonar)",       sonar["security_hotspots"], T["sonar_hotspots_max"]),
        evaluate("🌐 Alertes Hautes (ZAP)",        zap["High"],                T["zap_high_max"]),
        evaluate("⚡ Erreurs Runtime (Falco)",     falco["Error"],             T["falco_error_max"]),
        evaluate("🚨 Critiques Runtime (Falco)",   falco["Critical"],          T["falco_critical_max"]),
        evaluate("🎯 Score de Risque Global",       score,                     T["risk_score_max"]),
    ]

    all_passed = all(c["passed"] for c in checks)
    decision   = "✅  DÉPLOIEMENT AUTORISÉ" if all_passed else "🚫  DÉPLOIEMENT BLOQUÉ"
    timestamp  = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # ── Affichage console ─────────────────────────────────────────
    print(f"\n{'Vérification':<40} {'Valeur':>8}  {'Max':>6}  Résultat")
    print("─" * 72)
    for c in checks:
        print(f"  {c['label']:<38} {c['value']:>8}  {c['max_allowed']:>6}  {c['symbol']}")
    print("─" * 72)
    print(f"\n  Score global : {score}/100")
    print(f"\n  ╔══════════════════════════════════╗")
    print(f"  ║  {decision:<32}║")
    print(f"  ╚══════════════════════════════════╝\n")

    # ── Rapport texte (uploadé comme artefact) ────────────────────
    lines = [
        "═" * 60,
        "  Quality Gate Report — DevSecOps WebGoat",
        f"  Généré le : {timestamp}",
        f"  Run       : #{os.environ.get('GITHUB_RUN_NUMBER', '—')}",
        "═" * 60,
        "",
        f"{'Vérification':<40} {'Valeur':>8}  {'Max':>6}  Résultat",
        "─" * 72,
    ]
    for c in checks:
        lines.append(f"  {c['label']:<38} {c['value']:>8}  {c['max_allowed']:>6}  {c['symbol']}")
    lines += [
        "─" * 72,
        f"\n  Score global : {score}/100",
        f"\n  DÉCISION FINALE : {decision}",
        "",
        "Seuils appliqués (modifiables dans scripts/quality_gate.py) :",
    ]
    for key, val in THRESHOLDS.items():
        lines.append(f"  {key:<35} = {val}")

    report_text = "\n".join(lines)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as fh:
        fh.write(report_text)
    print(f"[OK] Rapport Quality Gate → {OUTPUT_FILE}")

    # ── Sortie pipeline ───────────────────────────────────────────
    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    main()
