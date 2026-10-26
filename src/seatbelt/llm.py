"""A minimal OpenAI-compatible chat client for the detector.

Separate from the benchmark's client on purpose: the detector is shipped code and
must not depend on benchmark tooling. Configuration comes from the environment,
and the timeout is short because this sits in the path of a tool call.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Mapping, Sequence

BASE_URL_ENV = "SEATBELT_LLM_BASE_URL"
API_KEY_ENV = "SEATBELT_LLM_API_KEY"
MODEL_ENV = "SEATBELT_LLM_MODEL"


class LLMError(RuntimeError):
    """The endpoint is unconfigured, unreachable or returned nonsense."""


@dataclass(frozen=True, slots=True)
class LLMConfig:
    base_url: str
    api_key: str
    model: str
    timeout: float = 2.0

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "LLMConfig":
        source = os.environ if env is None else env
        missing = [k for k in (BASE_URL_ENV, API_KEY_ENV, MODEL_ENV) if not source.get(k)]
        if missing:
            raise LLMError(
                "the detector needs " + ", ".join(missing) + "; set SEATBELT_NO_LLM=1 to disable it"
            )
        return cls(
            base_url=source[BASE_URL_ENV].rstrip("/"),
            api_key=source[API_KEY_ENV],
            model=source[MODEL_ENV],
            timeout=float(source.get("SEATBELT_LLM_TIMEOUT", "2.0")),
        )


class LLMClient:
    """One request, one reply, hard deadline."""

    def __init__(self, config: LLMConfig) -> None:
        self.config = config

    def chat(self, messages: Sequence[Mapping[str, str]]) -> str:
        payload = {
            "model": self.config.model,
            "messages": list(messages),
            "temperature": 0,
            "max_tokens": 120,
        }
        request = urllib.request.Request(
            f"{self.config.base_url}/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.config.api_key}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.config.timeout) as response:
                data = json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
            raise LLMError(str(exc)) from exc

        choices = data.get("choices") or []
        if not choices:
            raise LLMError("no choices in response")
        content = (choices[0].get("message") or {}).get("content")
        if isinstance(content, list):
            content = "".join(part.get("text", "") for part in content if isinstance(part, dict))
        if not isinstance(content, str) or not content.strip():
            raise LLMError("empty reply")
        return content