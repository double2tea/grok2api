"""Admin dashboard APIs for request history and traffic analytics."""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import orjson
from fastapi import APIRouter, Query
from fastapi.responses import Response

from app.platform.paths import log_dir as get_log_dir

router = APIRouter(prefix="/dashboard", tags=["Admin - Dashboard"])

_LINE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\s+\|\s+"
    r"(?P<level>[A-Z]+)\s+\|\s+[^-]+ - (?P<msg>.*)$"
)


def _log_files() -> list[Path]:
    base = get_log_dir()
    return sorted(base.glob("app_*.log"), reverse=True)


def _p95(values: list[int]) -> int | None:
    if not values:
        return None
    arr = sorted(values)
    idx = max(0, min(len(arr) - 1, int(len(arr) * 0.95) - 1))
    return arr[idx]


def _parse_structured_request(msg: str) -> dict[str, Any] | None:
    prefix = "request completed: "
    if not msg.startswith(prefix):
        return None

    raw = msg[len(prefix):].strip()
    try:
        payload = orjson.loads(raw)
    except Exception:
        return None

    if not isinstance(payload, dict):
        return None

    status = payload.get("status")
    latency_ms = payload.get("latency_ms")

    try:
        status = int(status)
    except (TypeError, ValueError):
        status = 0

    try:
        latency_ms = int(latency_ms)
    except (TypeError, ValueError):
        latency_ms = None

    return {
        "method": str(payload.get("method") or "-"),
        "path": str(payload.get("path") or "-"),
        "status": status,
        "latency_ms": latency_ms,
        "client": str(payload.get("client") or "-"),
        "forwarded_for": str(payload.get("forwarded_for") or "-"),
        "client_tag": str(payload.get("client_tag") or "-"),
        "auth_fp": str(payload.get("auth_fp") or "-"),
        "ua": str(payload.get("ua") or "-"),
        "cf_ray": str(payload.get("cf_ray") or "-"),
        "source": "request_log",
    }


def _parse_legacy_event(msg: str) -> dict[str, Any] | None:
    if "responses stream completed:" in msg:
        model = ""
        m = re.search(r"model=([^\s]+)", msg)
        if m:
            model = m.group(1)
        return {
            "method": "POST",
            "path": "/v1/responses",
            "status": 200,
            "latency_ms": None,
            "client": "-",
            "forwarded_for": "-",
            "client_tag": "-",
            "auth_fp": "-",
            "ua": "-",
            "cf_ray": "-",
            "source": "legacy",
            "model": model,
        }

    if "livekit session token fetched" in msg:
        return {
            "method": "GET",
            "path": "/webui/api/voice/token",
            "status": 200,
            "latency_ms": None,
            "client": "-",
            "forwarded_for": "-",
            "client_tag": "-",
            "auth_fp": "-",
            "ua": "-",
            "cf_ray": "-",
            "source": "legacy",
        }

    if "video job failed:" in msg:
        return {
            "method": "POST",
            "path": "/v1/videos",
            "status": 500,
            "latency_ms": None,
            "client": "-",
            "forwarded_for": "-",
            "client_tag": "-",
            "auth_fp": "-",
            "ua": "-",
            "cf_ray": "-",
            "source": "legacy",
        }

    return None


def _classify_capability(path: str) -> str:
    p = path.lower()
    if p.startswith("/v1/images"):
        return "image"
    if p.startswith("/v1/videos"):
        return "video"
    if p.startswith("/webui/api/voice"):
        return "voice"
    if p.startswith("/v1/chat/completions") or p.startswith("/v1/responses") or p.startswith("/v1/messages"):
        return "text"
    if p.startswith("/v1/models"):
        return "models"
    if p.startswith("/admin/"):
        return "admin"
    if p.startswith("/webui/"):
        return "webui"
    return "other"


def _resolve_model_name(event: dict[str, Any], capability: str) -> str:
    raw = str(event.get("model") or "").strip()
    if raw:
        return raw
    if capability == "image":
        return "image(unknown)"
    if capability == "video":
        return "video(unknown)"
    if capability == "text":
        return "text(unknown)"
    if capability == "voice":
        return "voice(unknown)"
    return "-"


def _iter_events(hours: int) -> list[dict[str, Any]]:
    now = datetime.now()
    since = now - timedelta(hours=hours)
    events: list[dict[str, Any]] = []

    for file in _log_files():
        try:
            lines = file.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue

        for ln in lines:
            m = _LINE_RE.match(ln)
            if not m:
                continue

            try:
                ts = datetime.strptime(m.group("ts"), "%Y-%m-%d %H:%M:%S.%f")
            except ValueError:
                continue

            if ts < since:
                continue

            msg = m.group("msg")
            payload = _parse_structured_request(msg) or _parse_legacy_event(msg)
            if not payload:
                continue

            payload["ts"] = ts.isoformat(timespec="seconds")
            events.append(payload)

    events.sort(key=lambda x: x["ts"], reverse=True)
    return events


def _contains(hay: str, needle: str) -> bool:
    return needle.lower() in hay.lower()


def _status_match(code: int, rule: str) -> bool:
    if not rule or rule == "all":
        return True
    if rule == "2xx":
        return 200 <= code < 300
    if rule == "4xx":
        return 400 <= code < 500
    if rule == "5xx":
        return 500 <= code < 600
    try:
        return code == int(rule)
    except ValueError:
        return True


def _event_match(
    e: dict[str, Any],
    *,
    path: str,
    status: str,
    source: str,
    client: str,
    client_tag: str,
    q: str,
) -> bool:
    if path and not _contains(str(e.get("path") or ""), path):
        return False

    code = int(e.get("status") or 0)
    if not _status_match(code, status):
        return False

    if source and source != "all" and str(e.get("source") or "") != source:
        return False

    if client and not _contains(str(e.get("client") or ""), client):
        return False

    if client_tag and not _contains(str(e.get("client_tag") or ""), client_tag):
        return False

    if q:
        flat = " ".join([
            str(e.get("method") or ""),
            str(e.get("path") or ""),
            str(e.get("client") or ""),
            str(e.get("client_tag") or ""),
            str(e.get("ua") or ""),
            str(e.get("auth_fp") or ""),
            str(e.get("source") or ""),
            str(e.get("model") or ""),
            str(e.get("capability") or ""),
        ])
        if not _contains(flat, q):
            return False

    return True


@router.get("/requests")
async def dashboard_requests(
    hours: int = Query(24, ge=1, le=168),
    limit: int = Query(300, ge=20, le=2000),
    path: str = Query(""),
    status: str = Query("all"),
    source: str = Query("all"),
    client: str = Query(""),
    client_tag: str = Query(""),
    q: str = Query(""),
):
    events = _iter_events(hours)

    filtered = [
        e for e in events
        if _event_match(
            e,
            path=path,
            status=status,
            source=source,
            client=client,
            client_tag=client_tag,
            q=q,
        )
    ]

    total = len(filtered)
    success = sum(1 for e in filtered if 200 <= int(e["status"]) < 400)
    error = sum(1 for e in filtered if int(e["status"]) >= 400)

    latency_vals = [int(e["latency_ms"]) for e in filtered if isinstance(e.get("latency_ms"), int)]
    avg_latency = int(sum(latency_vals) / len(latency_vals)) if latency_vals else None

    status_counter = Counter(int(e["status"]) for e in filtered if int(e["status"]) > 0)
    source_counter = Counter(str(e.get("source") or "unknown") for e in filtered)

    path_bucket: dict[str, dict[str, Any]] = defaultdict(lambda: {
        "path": "-",
        "count": 0,
        "error": 0,
        "latency_sum": 0,
        "latency_count": 0,
    })
    capability_bucket: dict[str, dict[str, Any]] = defaultdict(lambda: {
        "capability": "other",
        "count": 0,
        "error": 0,
        "latency_sum": 0,
        "latency_count": 0,
    })
    model_bucket: dict[str, dict[str, Any]] = defaultdict(lambda: {
        "model": "-",
        "count": 0,
        "error": 0,
        "latency_sum": 0,
        "latency_count": 0,
    })

    client_counter: Counter[str] = Counter()
    tag_counter: Counter[str] = Counter()

    for e in filtered:
        req_path = str(e.get("path") or "-")
        capability = _classify_capability(req_path)
        model_name = _resolve_model_name(e, capability)
        e["capability"] = capability
        e["model"] = model_name

        b = path_bucket[req_path]
        b["path"] = req_path
        b["count"] += 1

        cb = capability_bucket[capability]
        cb["capability"] = capability
        cb["count"] += 1

        mb = model_bucket[model_name]
        mb["model"] = model_name
        mb["count"] += 1

        status_code = int(e.get("status") or 0)
        if status_code >= 400:
            b["error"] += 1
            cb["error"] += 1
            mb["error"] += 1

        latency = e.get("latency_ms")
        if isinstance(latency, int):
            b["latency_sum"] += latency
            b["latency_count"] += 1
            cb["latency_sum"] += latency
            cb["latency_count"] += 1
            mb["latency_sum"] += latency
            mb["latency_count"] += 1

        c = str(e.get("client") or "-")
        t = str(e.get("client_tag") or "-")
        if c and c != "-":
            client_counter[c] += 1
        if t and t != "-":
            tag_counter[t] += 1

    path_stats = []
    for b in path_bucket.values():
        avg = int(b["latency_sum"] / b["latency_count"]) if b["latency_count"] else None
        path_stats.append({
            "path": b["path"],
            "count": b["count"],
            "error": b["error"],
            "avg_latency_ms": avg,
        })
    path_stats.sort(key=lambda x: x["count"], reverse=True)

    capability_stats = []
    for b in capability_bucket.values():
        avg = int(b["latency_sum"] / b["latency_count"]) if b["latency_count"] else None
        capability_stats.append({
            "capability": b["capability"],
            "count": b["count"],
            "error": b["error"],
            "avg_latency_ms": avg,
        })
    capability_stats.sort(key=lambda x: x["count"], reverse=True)

    model_stats = []
    for b in model_bucket.values():
        avg = int(b["latency_sum"] / b["latency_count"]) if b["latency_count"] else None
        model_stats.append({
            "model": b["model"],
            "count": b["count"],
            "error": b["error"],
            "avg_latency_ms": avg,
        })
    model_stats.sort(key=lambda x: x["count"], reverse=True)

    payload = {
        "filters": {
            "hours": hours,
            "path": path,
            "status": status,
            "source": source,
            "client": client,
            "client_tag": client_tag,
            "q": q,
            "limit": limit,
        },
        "summary": {
            "hours": hours,
            "total": total,
            "success": success,
            "error": error,
            "avg_latency_ms": avg_latency,
            "p95_latency_ms": _p95(latency_vals),
            "sources": dict(source_counter),
            "unique_clients": len(client_counter),
            "unique_client_tags": len(tag_counter),
        },
        "by_status": [
            {"status": code, "count": cnt}
            for code, cnt in sorted(status_counter.items(), key=lambda kv: kv[0])
        ],
        "by_path": path_stats[:20],
        "by_capability": capability_stats[:20],
        "by_model": model_stats[:20],
        "by_client": [
            {"client": client_ip, "count": count}
            for client_ip, count in client_counter.most_common(20)
        ],
        "by_client_tag": [
            {"client_tag": tag, "count": count}
            for tag, count in tag_counter.most_common(20)
        ],
        "recent": filtered[:limit],
    }

    return Response(content=orjson.dumps(payload), media_type="application/json")


__all__ = ["router"]
