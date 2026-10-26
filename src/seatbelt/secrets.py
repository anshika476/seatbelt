"""Secret discovery and egress matching.

Two-tier by design, because the two problems are different:

- **Short secrets** (API keys, tokens) are matched by exact value, plus the
  encodings an exfiltration attempt reaches for first — base64, base64url, hex,
  URL-encoded, JSON-escaped. Shingling a 40-character token would lose precision
  and drown the matcher in false positives.
- **Long untrusted text** is the taint store's job (``taint.py``), where shingles
  are the right tool. The two never share a matcher.

Privacy choices worth stating:

- Environment values are already in the guardian's memory, so registering them
  costs nothing extra.
- ``.env`` files in the workspace are read, because the agent can read them too.
- **Key files are registered by path, never by content.** ``~/.ssh/id_rsa`` is
  never opened; the path is enough to catch ``curl -d @~/.ssh/id_rsa``. The
  guardian should not hold a private key it does not need.

Values are held in memory for substring matching; only a salted digest is ever
written to a report or an audit record.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, Mapping
from urllib.parse import quote

#: Names that suggest a credential.
SECRET_NAME_RE = re.compile(
    r"(SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE|CREDENTIAL|APIKEY|API_KEY|ACCESS_KEY|_KEY$)",
    re.IGNORECASE,
)

#: Values that match a name but are obviously not secrets.
_NOT_SECRET = {
    "",
    "0",
    "1",
    "true",
    "false",
    "yes",
    "no",
    "null",
    "none",
    "changeme",
    "example",
    "dummy",
    "test",
}

#: Shortest value treated as a secret. Below this, matching is noise.
MIN_SECRET_LENGTH = 8

#: Credential files registered by path. Contents are never read.
KEY_FILE_PATTERNS = (
    ".ssh/id_rsa",
    ".ssh/id_ed25519",
    ".ssh/id_ecdsa",
    ".ssh/id_dsa",
    ".aws/credentials",
    ".npmrc",
    ".pypirc",
    ".netrc",
    ".docker/config.json",
    ".kube/config",
)


def _variants(value: str) -> Iterator[str]:
    """Every form a secret plausibly takes on the wire."""
    raw = value.encode("utf-8")
    yield value
    yield base64.b64encode(raw).decode("ascii")
    yield base64.urlsafe_b64encode(raw).decode("ascii")
    yield raw.hex()
    yield quote(value, safe="")
    yield json.dumps(value)[1:-1]


@dataclass(frozen=True, slots=True)
class Secret:
    label: str
    digest: str


class SecretRegistry:
    """Known secret values and known secret-bearing paths."""

    def __init__(self, salt: bytes | None = None) -> None:
        self._salt = salt or os.urandom(16)
        self._values: list[tuple[str, str]] = []  # (label, value)
        self._seen: set[str] = set()
        self._protected_paths: list[tuple[str, str]] = []  # (label, path)

    def __len__(self) -> int:
        return len(self._values)

    def digest(self, value: str) -> str:
        return hmac.new(self._salt, value.encode("utf-8"), hashlib.sha256).hexdigest()[:16]

    def add(self, label: str, value: str) -> bool:
        """Register a value. Returns False when it was skipped or already known."""
        candidate = (value or "").strip()
        if len(candidate) < MIN_SECRET_LENGTH or candidate.lower() in _NOT_SECRET:
            return False
        key = f"{label}\0{candidate}"
        if key in self._seen:
            return False
        self._seen.add(key)
        self._values.append((label, candidate))
        return True

    def protect_path(self, label: str, path: str) -> None:
        resolved = os.path.realpath(os.path.expanduser(path))
        if all(existing != resolved for _, existing in self._protected_paths):
            self._protected_paths.append((label, resolved))

    @property
    def protected_paths(self) -> tuple[tuple[str, str], ...]:
        return tuple(self._protected_paths)

    # -- discovery -------------------------------------------------------- #

    def discover_env(self, env: Mapping[str, str] | None = None) -> int:
        source = os.environ if env is None else env
        added = 0
        for name, value in source.items():
            if SECRET_NAME_RE.search(name) and self.add(f"env:{name}", value):
                added += 1
        return added

    def discover_dotenv(self, path: str | os.PathLike[str]) -> int:
        file = Path(path)
        if not file.is_file():
            return 0
        try:
            text = file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return 0
        added = 0
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            name, _, value = stripped.partition("=")
            value = value.strip().strip("'\"")
            if self.add(f"file:{file.name}:{name.strip()}", value):
                added += 1
        return added

    def protect_known_key_files(self, home: str) -> int:
        """Register credential paths by name. The files are never opened."""
        added = 0
        for relative in KEY_FILE_PATTERNS:
            candidate = os.path.join(home, relative)
            if os.path.exists(candidate):
                self.protect_path(f"keyfile:{relative}", candidate)
                added += 1
        return added

    # -- matching --------------------------------------------------------- #

    def contains(self, text: str) -> str | None:
        """Return the label of a secret appearing in ``text``, if any."""
        if not text:
            return None
        for label, value in self._values:
            if any(variant and variant in text for variant in _variants(value)):
                return label
        return None

    def referenced_path(self, text: str) -> str | None:
        """Return a protected path mentioned in ``text``, if any."""
        if not text:
            return None
        for label, path in self._protected_paths:
            candidates = {path, os.path.basename(path), f"~/{os.path.relpath(path, os.path.expanduser('~'))}" if path.startswith(os.path.expanduser("~")) else path}
            if any(candidate and candidate in text for candidate in candidates):
                return label
        return None

    def redact(self, text: str) -> str:
        if not text:
            return text
        for label, value in self._values:
            for variant in _variants(value):
                if variant and variant in text:
                    text = text.replace(variant, f"[redacted:{label}]")
        return text


def build_registry(
    *,
    workspace: str,
    home: str,
    env: Mapping[str, str] | None = None,
) -> SecretRegistry:
    """Assemble the registry a guardian process should start with."""
    registry = SecretRegistry()
    registry.discover_env(env)
    registry.discover_dotenv(os.path.join(workspace, ".env"))
    registry.protect_known_key_files(home)
    registry.protect_path("dotenv", os.path.join(workspace, ".env"))
    return registry


def labels(registry: SecretRegistry) -> Iterable[str]:
    return [label for label, _ in registry._values]