"""
scripts/notify_slack.py
──────────────────────────────────────────────────────────────────────────────
Notification Slack — envoie un résumé du pipeline DevSecOps après chaque run.
Lit les rapports disponibles et poste un message structuré avec blocs Slack.

Variable d'environnement requise :
  SLACK_WEBHOOK_URL  →  Webhook entrant Slack (Slack App → Incoming Webhooks)
──────────────────────────────────────────────────────────────────────────────
"""

import json
import os
import sys
import urllib.request
from datetime import datetime, timezone

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS — lecture des métriques
# ─────────────────────────────────────────────────────────────────────────────

def _load_json(path: str):
    if not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def _read_quality_gate() -> tuple[str, str]:
    """Retourne (décision, score) depuis le rapport Quality Gate."""
    if not os.path.isfile("quality-gate-report.txt"):
        return "INCONNU", "—"
    try:
        with open("quality-gate-report.txt", encoding="utf-8") as fh:
            content = fh.read()
        if "DÉPLOIEMENT AUTORISÉ" in content:
            decision = "✅ AUTORISÉ"
        elif "DÉPLOIEMENT BLOQUÉ" in content:
            decision = "🚫 BLOQUÉ"
        else:
            decision = "⚠️ INCONNU"

        # Extrait le score
        import re
        m = re.search(r"Score global\s*:\s*(\d+)/100", content)
        score = m.group(1) + "/100" if m else "—"
        return decision, score
    except Exception:
        return "INCONNU", "—"


def get_metrics() -> dict:
    metrics = {
        "secrets":    0,
        "cve_critical": 0,
        "cve_high":   0,
        "sonar_vuln": 0,
        "zap_high":   0,
        "falco_error": 0,
    }

    # Gitleaks
    for path in ("results.sarif", "gitleaks-report.json"):
        data = _load_json(path)
        if data is None:
            continue
        if isinstance(data, list):
            metrics["secrets"] = len(data)
        elif isinstance(data, dict) and "runs" in data:
            metrics["secrets"] = len(data["runs"][0].get("results", []))
        break

    # Trivy
    trivy = _load_json("trivy-results.json")
    if trivy:
        for result in trivy.get("Results", []):
            for vuln in result.get("Vulnerabilities", []):
                sev = vuln.get("Severity", "").lower()
                if sev == "critical":
                    metrics["cve_critical"] += 1
                elif sev == "high":
                    metrics["cve_high"] += 1

    # SonarCloud
    sonar = _load_json("sonar-results.json")
    if sonar:
        for m in sonar.get("component", {}).get("measures", []):
            if m.get("metric") == "vulnerabilities":
                metrics["sonar_vuln"] = int(m.get("value", 0))

    # ZAP
    zap = _load_json("report_json.json")
    if zap:
        for site in zap.get("site", []):
            for alert in site.get("alerts", []):
                if alert.get("riskdesc", "").startswith("High"):
                    metrics["zap_high"] += 1

    # Falco
    if os.path.isfile("falco-results.json"):
        try:
            with open("falco-results.json", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        log = json.loads(line)
                        if log.get("priority", "").lower() in ("error", "critical"):
                            metrics["falco_error"] += 1
                    except json.JSONDecodeError:
                        pass
        except Exception:
            pass

    return metrics


# ─────────────────────────────────────────────────────────────────────────────
# CONSTRUCTION DU MESSAGE SLACK (Block Kit)
# ─────────────────────────────────────────────────────────────────────────────

def build_slack_payload(metrics: dict, decision: str, score: str) -> dict:
    run_number = os.environ.get("GITHUB_RUN_NUMBER", "—")
    actor      = os.environ.get("GITHUB_ACTOR", "—")
    branch     = os.environ.get("GITHUB_REF_NAME", "—")
    sha        = os.environ.get("GITHUB_SHA", "")[:8] or "—"
    run_url    = os.environ.get("GITHUB_RUN_URL", "#")
    timestamp  = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    repo       = os.environ.get("GITHUB_REPOSITORY", "—")

    # Couleur latérale selon la décision
    color = "#22c55e" if "AUTORISÉ" in decision else "#ef4444"

    # Ligne de métriques
    def _badge(label: str, val: int, warn: int = 1) -> str:
        icon = "🔴" if val >= warn else "🟢"
        return f"{icon} *{label}* : `{val}`"

    metrics_text = "  ".join([
        _badge("Secrets",      metrics["secrets"],     warn=1),
        _badge("CVE Crit.",    metrics["cve_critical"], warn=1),
        _badge("CVE High",     metrics["cve_high"],     warn=6),
        _badge("SAST Vuln.",   metrics["sonar_vuln"],   warn=11),
        _badge("ZAP High",     metrics["zap_high"],     warn=1),
        _badge("Falco Err.",   metrics["falco_error"],  warn=6),
    ])

    payload = {
        "attachments": [
            {
                "color": color,
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": "🛡️ DevSecOps Pipeline — Rapport de Sécurité",
                        },
                    },
                    {"type": "divider"},
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*Projet :*\n`{repo}`"},
                            {"type": "mrkdwn", "text": f"*Branche :*\n`{branch}`"},
                            {"type": "mrkdwn", "text": f"*Run :*\n`#{run_number}`"},
                            {"type": "mrkdwn", "text": f"*Commit :*\n`{sha}`"},
                            {"type": "mrkdwn", "text": f"*Déclenché par :*\n`{actor}`"},
                            {"type": "mrkdwn", "text": f"*Date :*\n`{timestamp}`"},
                        ],
                    },
                    {"type": "divider"},
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*Métriques de sécurité :*\n{metrics_text}",
                        },
                    },
                    {"type": "divider"},
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*Score de Risque :*\n`{score}`"},
                            {"type": "mrkdwn", "text": f"*Déploiement :*\n{decision}"},
                        ],
                    },
                    {
                        "type": "actions",
                        "elements": [
                            {
                                "type": "button",
                                "text": {"type": "plain_text", "text": "📊 Voir le Dashboard"},
                                "url": run_url,
                                "style": "primary",
                            },
                            {
                                "type": "button",
                                "text": {"type": "plain_text", "text": "🔗 GitHub Actions"},
                                "url": run_url,
                            },
                        ],
                    },
                ],
            }
        ]
    }
    return payload


# ─────────────────────────────────────────────────────────────────────────────
# ENVOI DU WEBHOOK
# ─────────────────────────────────────────────────────────────────────────────

def send_notification(payload: dict) -> bool:
    webhook_url = os.environ.get("SLACK_WEBHOOK_URL", "")
    if not webhook_url:
        print("[WARN] SLACK_WEBHOOK_URL non définie — notification ignorée.")
        return True   # Ne pas faire échouer le pipeline pour ça

    body = json.dumps(payload).encode("utf-8")
    req  = urllib.request.Request(
        webhook_url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            status = resp.getcode()
            if status == 200:
                print("[OK]  Notification Slack envoyée avec succès.")
                return True
            else:
                print(f"[WARN] Slack a répondu avec le code {status}.", file=sys.stderr)
                return False
    except Exception as exc:
        print(f"[ERROR] Envoi Slack échoué : {exc}", file=sys.stderr)
        return False


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print("\n" + "═" * 60)
    print("  Notification Slack — Pipeline DevSecOps")
    print("═" * 60)

    print("\n[1/3] Lecture des métriques…")
    metrics  = get_metrics()

    print("[2/3] Lecture du résultat Quality Gate…")
    decision, score = _read_quality_gate()

    print("[3/3] Envoi de la notification Slack…")
    payload = build_slack_payload(metrics, decision, score)
    ok      = send_notification(payload)

    print("═" * 60 + "\n")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
