"""The local language model: which models the laptop's Ollama server offers.

Only ``localhost`` endpoints are allowed (config.save_settings checks this).
"""
from __future__ import annotations

import json
from urllib.error import URLError
from urllib.request import HTTPRedirectHandler, build_opener

from .config import load_settings


def models() -> dict:
    settings = load_settings()
    endpoint = settings["llm_endpoint"].rstrip("/")
    try:
        with urlopen(f"{endpoint}/api/tags", timeout=2) as response:
            names = sorted(m["name"] for m in json.load(response).get("models", []))
        online, error = True, ""
    except (URLError, OSError, ValueError) as exc:
        names, online, error = [], False, str(getattr(exc, "reason", exc))
    selected = settings["llm_model"]
    return {"endpoint": endpoint, "online": online, "error": error, "selected": selected,
            "models": names if selected in names else [selected, *names],
            "installed": names}


class _NoRedirect(HTTPRedirectHandler):
    """Ollama never redirects; anything that tries is refused rather than followed off the laptop."""
    def redirect_request(self, *args, **kwargs):
        return None


urlopen = build_opener(_NoRedirect).open


class ModelUnavailable(ValueError):
    """The local model did not answer (Ollama not running, model not pulled, or too slow)."""


def chat(system: str, user: str, *, json_mode: bool = True, timeout: float = 180.0) -> str:
    """One answer from the local model (Ollama's /api/chat on this laptop). Nothing leaves the laptop:
    the endpoint is limited to localhost by config.save_settings."""
    from urllib.request import Request

    settings = load_settings()
    endpoint = settings["llm_endpoint"].rstrip("/")
    body = {"model": settings["llm_model"], "stream": False, "options": {"temperature": 0},
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
    if json_mode:
        body["format"] = "json"
    request = Request(f"{endpoint}/api/chat", data=json.dumps(body).encode("utf-8"), headers={"Content-Type": "application/json"})
    try:
        with urlopen(request, timeout=timeout) as response:
            return json.load(response)["message"]["content"]
    except (URLError, OSError, ValueError, KeyError) as exc:
        raise ModelUnavailable(f"The local model ({settings['llm_model']}) did not answer: "
                               f"{getattr(exc, 'reason', exc)}. Start Ollama on this laptop and try again.") from None
