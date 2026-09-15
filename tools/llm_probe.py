"""One-shot OpenAI Responses API probe; credentials are prompt-only and never logged."""
from __future__ import annotations

import getpass
import json
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse


def main() -> int:
    base = input("Base URL (for example https://host/v1): ").strip().rstrip("/")
    model = input("Model ID: ").strip()
    key = getpass.getpass("API key (hidden): ")
    parsed = urlparse(base)
    if parsed.scheme != "https" or not parsed.netloc or any(x in base.lower() for x in ("@", "?", "#")):
        print("REJECTED: base URL must be HTTPS without credentials or query data")
        return 2
    if not model or not key or any(ord(c) <= 32 for c in key):
        print("REJECTED: model or key is empty/invalid")
        return 2
    payload = {"model": model, "input": "Reply with exactly: probe-ok",
               "max_output_tokens": 16, "stream": True}
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(
        base + "/responses", data=raw,
        headers={
            "Authorization": "Bearer " + key,
            "Content-Type": "application/json",
            "Accept": "text/event-stream",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/140.0 Safari/537.36",
        },
        method="POST")
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            body = response.read(256 * 1024 + 1)
            status = response.status
    except urllib.error.HTTPError as exc:
        error_body = exc.read(64 * 1024)
        detail = ""
        try:
            parsed_error = json.loads(error_body.decode("utf-8"))
            error = parsed_error.get("error", {}) if isinstance(parsed_error, dict) else {}
            if isinstance(error, dict):
                detail = json.dumps(
                    {k: error.get(k) for k in ("type", "code", "message") if error.get(k)},
                    ensure_ascii=False,
                )
            if not detail and isinstance(parsed_error, dict):
                detail = json.dumps({"top_level_keys": sorted(parsed_error.keys())}, ensure_ascii=False)
        except (UnicodeError, ValueError, TypeError, AttributeError):
            pass
        print(f"HTTP_ERROR status={exc.code} elapsed={time.monotonic() - started:.2f}s detail={detail or '<non-json>'}")
        return 1
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        print(f"TRANSPORT_ERROR type={type(exc).__name__} elapsed={time.monotonic() - started:.2f}s")
        return 1
    finally:
        key = None
    if len(body) > 256 * 1024:
        print("REJECTED: response exceeds 256 KiB")
        return 1
    try:
        raw_text = body.decode("utf-8")
        parts: list[str] = []
        reported_model = None
        usage_present = False
        for line in raw_text.splitlines():
            if not line.startswith("data:"):
                continue
            data = json.loads(line[5:].strip())
            reported_model = data.get("model") or reported_model
            if data.get("type") == "response.output_text.delta" and isinstance(data.get("delta"), str):
                parts.append(data["delta"])
            if data.get("type") in {"response.completed", "response.done"}:
                response = data.get("response") or data.get("output") or {}
                if isinstance(response, dict):
                    reported_model = response.get("model") or reported_model
                    usage_present = isinstance(response.get("usage"), dict)
            if data.get("type") in {"response.failed", "error"}:
                print("UPSTREAM_STREAM_ERROR")
                return 1
        reply = "".join(parts) or None
        print(json.dumps({"status": status, "elapsed_seconds": round(time.monotonic() - started, 2),
                          "reported_model": reported_model,
                          "reply_received": isinstance(reply, str) and bool(reply),
                          "usage_present": usage_present}, ensure_ascii=False))
        return 0 if isinstance(reply, str) and reply else 1
    except (UnicodeError, ValueError, TypeError, KeyError, IndexError):
        print(f"INVALID_JSON status={status} elapsed={time.monotonic() - started:.2f}s")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
