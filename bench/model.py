"""Minimal OpenAI-compatible chat client.

No SDK: the benchmark talks to whatever endpoint the operator points it at with
``urllib``, so it works against vLLM, llama.cpp, Ollama, OpenRouter or a hosted
API without a dependency. Configuration comes only from the environment.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Sequence

BASE_URL_ENV = "SEATBELT_BENCH_BASE_URL"
API_KEY_ENV = "SEATBELT_BENCH_API_KEY"
MODEL_ENV = "SEATBELT_BENCH_MODEL"


class ModelError(RuntimeError):
    """The endpoint is not configured or did not answer usefully."""


@dataclass(frozen=True, slots=True)
class ModelConfig:
    base_url: str
    api_key: str
    model: str
    temperature: float = 0.0
    timeout: float = 120.0
    max_retries: int = 3

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "ModelConfig":
        source = os.environ if env is None else env
        missing = [
            name for name in (BASE_URL_ENV, API_KEY_ENV, MODEL_ENV) if not source.get(name)
        ]
        if missing:
            raise ModelError(
                "the live benchmark needs "
                + ", ".join(missing)
                + " (see bench/README.md); use --mode replay to run without a model"
            )
        return cls(
            base_url=source[BASE_URL_ENV].rstrip("/"),
            api_key=source[API_KEY_ENV],
            model=source[MODEL_ENV],
            temperature=float(source.get("SEATBELT_BENCH_TEMPERATURE", "0")),
        )

    def redacted(self) -> dict[str, Any]:
        return {"base_url": self.base_url, "model": self.model, "temperature": self.temperature}


class Client:
    """Chat completions with retries on transport errors and 5xx."""

    def __init__(self, config: ModelConfig) -> None:
        self.config = config
        self.calls = 0
        self.prompt_tokens = 0
        self.completion_tokens = 0

    def chat(self, messages: Sequence[dict[str, str]]) -> str:
        payload = {
            "model": self.config.model,
            "messages": list(messages),
            "temperature": self.config.temperature,
        }
        body = json.dumps(payload).encode("utf-8")
        url = f"{self.config.base_url}/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.config.api_key}",
        }

        last_error: Exception | None = None
        for attempt in range(self.config.max_retries):
            request = urllib.request.Request(url, data=body, headers=headers, method="POST")
            try:
                with urllib.request.urlopen(request, timeout=self.config.timeout) as response:
                    data = json.loads(response.read().decode("utf-8"))
                self.calls += 1
                usage = data.get("usage") or {}
                self.prompt_tokens += int(usage.get("prompt_tokens") or 0)
                self.completion_tokens += int(usage.get("completion_tokens") or 0)
                return _extract_text(data)
            except urllib.error.HTTPError as exc:
                detail = exc.read().decode("utf-8", "replace")[:500]
                last_error = ModelError(f"HTTP {exc.code} from {url}: {detail}")
                if exc.code < 500 and exc.code != 429:
                    raise last_error from exc
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
                last_error = ModelError(f"could not reach {url}: {exc}")
            time.sleep(1.5 * (attempt + 1))

        raise last_error or ModelError("the model endpoint failed")


def _extract_text(data: dict[str, Any]) -> str:
    choices = data.get("choices") or []
    if not choices:
        raise ModelError(f"no choices in response: {json.dumps(data)[:300]}")
    message = choices[0].get("message") or {}
    content = message.get("content")
    if isinstance(content, list):
        # Some servers return content as parts.
        content = "".join(
            part.get("text", "") for part in content if isinstance(part, dict)
        )
    if not isinstance(content, str) or not content.strip():
        raise ModelError("the model returned an empty message")
    return content