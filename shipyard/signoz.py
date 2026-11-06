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
