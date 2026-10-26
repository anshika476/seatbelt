"""Taint tracking for untrusted content.

When the agent reads text it does not control — a web page, an issue body, a file
outside the workspace — that text may end up inside a command, a URL or a file
write. Shingles let us notice that without keeping the whole document: hash every
64-character window, keep the hashes in a capped LRU, and later shingle the
outbound payload and intersect.

This is provenance, not secrecy: a shingle match says "this text came from
somewhere untrusted", which is a reason to ask a human before it leaves the
machine. It is never a reason to allow something.

Sizing: a 64-character window makes an accidental collision on prose very
unlikely while still catching a paragraph pasted into a query string. The store
is capped so a large fetch cannot grow memory without bound; the oldest shingles
are evicted first.
"""

from __future__ import annotations

import base64
import hashlib
import re
from collections import OrderedDict
from typing import Iterable

SHINGLE_SIZE = 64
DEFAULT_CAPACITY = 4096

#: Store every fourth window: enough coverage to catch a pasted paragraph
#: without keeping a hash per character.
MAX_ADD_STRIDE = 16

#: Longest candidate we scan at match time.
MAX_MATCH_CHARS = 8192

_WHITESPACE = re.compile(r"\s+")


def _normalise(text: str) -> str:
    """Collapse whitespace so reflowed text still matches."""
    return _WHITESPACE.sub(" ", text).strip()


def shingles(text: str, size: int = SHINGLE_SIZE, stride: int = 1) -> Iterable[str]:
    """Hashed character windows of ``text``.

    ``stride`` trades coverage against cost. Storing uses a wide stride to keep
    the cap meaningful; matching uses stride 1, because a payload can contain the
    text at any offset and aligned windows alone would miss ``?q=<paragraph>``
    whenever the prefix happened to shift the alignment.
    """
    normalised = _normalise(text)
    if len(normalised) < size:
        if normalised:
            yield hashlib.sha256(normalised.encode("utf-8")).hexdigest()[:16]
        return
    for start in range(0, len(normalised) - size + 1, max(1, stride)):
        window = normalised[start : start + size]
        yield hashlib.sha256(window.encode("utf-8")).hexdigest()[:16]


def _decoded_forms(text: str) -> Iterable[str]:
    """Text and any base64 blobs it contains, so encoding does not hide it."""
    yield text
    for candidate in re.findall(r"[A-Za-z0-9+/=]{32,}", text):
        try:
            decoded = base64.b64decode(candidate + "=" * (-len(candidate) % 4), validate=True)
        except (ValueError, TypeError):
            continue
        try:
            yield decoded.decode("utf-8")
        except UnicodeDecodeError:
            continue


class TaintStore:
    """Capped store of shingle → source label."""

    def __init__(self, capacity: int = DEFAULT_CAPACITY) -> None:
        self.capacity = capacity
        self._store: OrderedDict[str, str] = OrderedDict()

    def __len__(self) -> int:
        return len(self._store)

    def add(self, source: str, text: str) -> int:
        """Mark ``text`` as coming from ``source``. Returns shingles added."""
        added = 0
        for form in _decoded_forms(text or ""):
            for shingle in shingles(form, stride=MAX_ADD_STRIDE):
                if shingle in self._store:
                    self._store.move_to_end(shingle)
                    continue
                self._store[shingle] = source
                added += 1
                if len(self._store) > self.capacity:
                    self._store.popitem(last=False)
        return added

    def match(self, text: str) -> str | None:
        """Return the source of any shingle of ``text`` we have seen before.

        Matching scans every offset, because the stored text may appear anywhere
        in a longer payload. The candidate is bounded so a huge argument cannot
        turn this into a denial of service against the guardian.
        """
        if not text or not self._store:
            return None
        for form in _decoded_forms(text[:MAX_MATCH_CHARS]):
            for shingle in shingles(form, stride=1):
                source = self._store.get(shingle)
                if source:
                    return source
        return None

    @property
    def sources(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(self._store.values()))