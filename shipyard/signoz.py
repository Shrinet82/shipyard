"""Read-only SigNoz connection: firing alerts, alert rules, recent logs; and SigNoz's alert webhook turned into a Shipyard alert.

Authentication is SigNoz's own `SigNoz-Api-Key` header. Give Shipyard a key of a VIEWER service account: it can read and nothing else.
Everything that comes back is data, never instructions: it is redacted, defused and clipped like Coolify's logs.
"""
from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
from typing import Any, Callable

from .evidence import clean_lines

SERVICE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
MAX_MINUTES = 24 * 60
MAX_LOGS = 100
SERVICE_LABELS = ("service.name", "service_name", "k8s.deployment.name", "k8s_deployment_name", "deployment", "app", "service")


class SigNozError(Exception):
    pass


def _http(method: str, url: str, headers: dict[str, str], body: Any = None, timeout: float = 20.0) -> tuple[int, Any]:
    req = urllib.request.Request(url, method=method, headers={"Content-Type": "application/json", **headers},
                                 data=json.dumps(body).encode() if body is not None else None)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            return r.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read() or b"{}")
        except ValueError:
            return exc.code, {}
    except (urllib.error.URLError, OSError) as exc:
        raise SigNozError(f"cannot reach SigNoz at {url.split('/api')[0]}: {exc}") from None


class SigNoz:
    def __init__(self, url: str, api_key: str, http: Callable[..., tuple[int, Any]] = _http, now: Callable[[], float] = time.time):
        self.url, self.key, self._http, self.now = url.rstrip("/"), api_key.strip(), http, now

    def _call(self, method: str, path: str, body: Any = None) -> Any:
        status, data = self._http(method, self.url + path, {"SigNoz-Api-Key": self.key}, body)
        if status in (401, 403):
            raise SigNozError("SigNoz refused the API key (is it a service-account key that has not expired?)")
        if status >= 400 or not isinstance(data, dict):
            msg = (((data or {}).get("error") or {}).get("message") if isinstance(data, dict) else "") or ""
            raise SigNozError(f"SigNoz answered {status}: {msg}"[:200])
        return data.get("data")

    # -- checks -----------------------------------------------------------------------------

    def health(self) -> bool:
        status, data = self._http("GET", self.url + "/api/v2/healthz", {})
        return status == 200 and bool(((data or {}).get("data") or {}).get("healthy"))

    def check(self) -> str:
        """Prove the address and the key work; returns what was learned."""
        if not self.health():
            raise SigNozError("SigNoz does not answer its health check")
        alerts = self._call("GET", "/api/v1/alerts")
        return f"SigNoz is healthy and the key can read ({len(alerts or [])} alert(s) firing now)"

    # -- reads ------------------------------------------------------------------------------

    def alerts(self) -> list[dict[str, Any]]:
        return [a for a in (self._call("GET", "/api/v1/alerts") or []) if isinstance(a, dict)]

    def rules(self) -> list[dict[str, Any]]:
        return [r for r in (self._call("GET", "/api/v2/rules") or []) if isinstance(r, dict)]

    def logs(self, service: str, minutes: int = 15, errors_only: bool = False, limit: int = 30) -> list[str]:
        if not SERVICE.match(service or ""):
            raise SigNozError("a service name is letters, digits and . _ - : /")
        minutes, limit = max(1, min(int(minutes), MAX_MINUTES)), max(1, min(int(limit), MAX_LOGS))
        end = int(self.now() * 1000)
        expr = f"service.name = '{service}'" + (" AND severity_text IN ('ERROR', 'FATAL', 'CRITICAL', 'error', 'fatal', 'critical')" if errors_only else "")
        query = {"schemaVersion": "v1", "start": end - minutes * 60_000, "end": end, "requestType": "raw",
                 "compositeQuery": {"queries": [{"type": "builder_query", "spec": {
                     "name": "A", "signal": "logs", "limit": limit, "filter": {"expression": expr},
                     "order": [{"key": {"name": "timestamp"}, "direction": "desc"}]}}]}}
        data = self._call("POST", "/api/v5/query_range", query) or {}
        results = (((data.get("data") or {}).get("results")) or [])
        rows = (results[0].get("rows") if results else None) or []
        lines = []
        for row in reversed(rows):                                  # newest first from SigNoz; show oldest first
            d = row.get("data") or {}
            ts = str(row.get("timestamp") or d.get("timestamp") or "")[:19]
            lines.append(f"{ts} {d.get('severity_text', '')} {d.get('body', '')}".strip())
        return clean_lines(lines, limit)


# -- text for chat -----------------------------------------------------------------------------

def _label(alert: dict[str, Any], *names: str) -> str:
    labels = alert.get("labels") or {}
    for n in names:
        if labels.get(n):
            return str(labels[n])
    return ""


def alert_service(alert: dict[str, Any]) -> str:
    return _label(alert, *SERVICE_LABELS)


def describe_alerts(alerts: list[dict[str, Any]], limit: int = 10) -> str:
    firing = [a for a in alerts if ((a.get("status") or {}).get("state") or "active") in ("active", "firing")]
    if not firing:
        return "SigNoz: no alerts are firing."
    out = [f"SigNoz: {len(firing)} alert(s) firing"]
    for a in firing[:limit]:
        name = _label(a, "alertname") or "alert"
        sev = _label(a, "severity")
        svc = alert_service(a)
        note = (a.get("annotations") or {}).get("summary") or (a.get("annotations") or {}).get("description") or ""
        since = str(a.get("startsAt") or "")[:19]
        out.append(f"- {name}" + (f" [{sev}]" if sev else "") + (f" on {svc}" if svc else "") + f" since {since}" + (f": {note}" if note else ""))
    if len(firing) > limit:
        out.append(f"({len(firing) - limit} more)")
    return "\n".join(clean_lines(out, 40))


def describe_rules(rules: list[dict[str, Any]], limit: int = 15) -> str:
    if not rules:
        return "SigNoz has no alert rules yet."
    out = [f"SigNoz: {len(rules)} alert rule(s)"]
    for r in rules[:limit]:
        severity = (r.get("labels") or {}).get("severity")
        out.append(f"- {r.get('alert') or r.get('name') or 'rule'}: {r.get('state') or 'unknown'}" + (f" [{severity}]" if severity else ""))
    return "\n".join(clean_lines(out, 40))


# -- SigNoz's webhook -> Shipyard alerts ------------------------------------------------------------------

def parse_webhook(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """SigNoz posts Alertmanager's format: {status, alerts: [{status, labels, annotations, startsAt, fingerprint}]}. Firing alerts only."""
    out = []
    for a in payload.get("alerts") or []:
        if isinstance(a, dict) and a.get("status", payload.get("status")) == "firing":
            out.append(a)
    return out[:20]


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")[:40] or "alert"


# -- a fresh SigNoz: make the admin, a read-only key and (optionally) an alert that calls Shipyard ---------------------------------

def _plain(http: Callable[..., tuple[int, Any]], method: str, url: str, token: str = "", body: Any = None) -> Any:
    status, data = http(method, url, {"Authorization": f"Bearer {token}"} if token else {}, body)
    if status >= 400 or not isinstance(data, dict):
        msg = (((data or {}).get("error") or {}).get("message") if isinstance(data, dict) else "") or ""
        raise SigNozError(f"SigNoz answered {status} for {url.split('/api')[-1][:40]}: {msg}"[:220])
    return data


def bootstrap(url: str, *, http: Callable[..., tuple[int, Any]] = _http, now: Callable[[], float] = time.time,
              make_password: Callable[[], str] | None = None, login: tuple[str, str] | None = None) -> dict[str, str]:
    """For a SigNoz nobody has set up yet: create the admin account, then a Viewer service account with a one-year key.
    Returns the admin's login, a session token (for `create_alert`) and the read-only key."""
    import secrets
    url = url.rstrip("/")
    info = _plain(http, "GET", url + "/api/v1/version")
    if info.get("setupCompleted") and not login:
        raise SigNozError("this SigNoz already has an admin. Create a Viewer service account and key in its settings, then run connect signoz without --bootstrap")
    if info.get("setupCompleted"):
        email, password = login                                   # an admin made earlier by this tool: use it to make a new key
    else:
        password = (make_password or (lambda: secrets.token_urlsafe(18) + "Aa1!"))()
        email = "admin@shipyard.local"
        _plain(http, "POST", url + "/api/v1/register", body={"name": "shipyard", "orgName": "shipyard", "email": email, "password": password})
    from urllib.parse import quote
    ctx = _plain(http, "GET", f"{url}/api/v2/sessions/context?email={quote(email)}&ref={quote(url, safe='')}")
    org = ctx["data"]["orgs"][0]["id"]
    token = _plain(http, "POST", url + "/api/v2/sessions/email_password", body={"email": email, "password": password, "orgId": org})["data"]["accessToken"]
    accounts = _plain(http, "GET", url + "/api/v1/service_accounts", token).get("data") or []
    existing = next((a["id"] for a in accounts if a.get("name") == "shipyard-readonly"), None)
    sa = existing or _plain(http, "POST", url + "/api/v1/service_accounts", token, {"name": "shipyard-readonly"})["data"]["id"]
    roles = _plain(http, "GET", url + "/api/v1/roles", token)["data"]
    viewer = next((r["id"] for r in roles if "viewer" in str(r.get("name", "")).lower()), None)
    if not viewer:
        raise SigNozError("SigNoz has no Viewer role")
    if not existing:
        _plain(http, "POST", url + "/api/v1/service_account_roles", token, {"roleId": viewer, "serviceAccountId": sa})
    key = _plain(http, "POST", f"{url}/api/v1/service_accounts/{sa}/keys", token, {"name": f"shipyard-{int(now())}", "expiresAt": int(now() + 365 * 86400)})["data"]["key"]
    return {"admin_email": email, "admin_password": password, "token": token, "key": key}


def create_alert(url: str, token: str, webhook_url: str, *, http: Callable[..., tuple[int, Any]] = _http, name: str = "Errors in your apps") -> None:
    """A webhook channel that calls Shipyard, and a rule: any service logging ERROR in 5 minutes fires it (checked every minute)."""
    url = url.rstrip("/")
    _plain(http, "POST", url + "/api/v1/channels", token, {"name": "shipyard", "webhook_configs": [{"url": webhook_url, "send_resolved": True}]})
    rule = {"alert": name, "alertType": "LOGS_BASED_ALERT", "ruleType": "threshold_rule", "version": "v5",
            "condition": {"compositeQuery": {"queryType": "builder", "panelType": "graph", "unit": "",
                          "queries": [{"type": "builder_query", "spec": {
                              "name": "A", "signal": "logs", "stepInterval": 60, "disabled": False, "aggregations": [{"expression": "count()"}],
                              "filter": {"expression": "severity_text = 'ERROR'"},
                              "groupBy": [{"name": "service.name", "fieldContext": "resource", "fieldDataType": "string"}]}}]},
                          "selectedQueryName": "A", "alertOnAbsent": False, "target": 0, "op": "1", "matchType": "1"},
            "evaluation": {"kind": "rolling", "spec": {"evalWindow": "5m0s", "frequency": "1m0s"}},
            "labels": {"severity": "critical"},
            "annotations": {"summary": "A service logged ERROR lines in the last 5 minutes", "description": "At least one ERROR log line; the labels name the service"},
            "preferredChannels": ["shipyard"]}
    _plain(http, "POST", url + "/api/v2/rules", token, rule)
