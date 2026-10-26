"""A tiny stand-in for an OpenAI-compatible endpoint.

Two uses:

1. CI and the demo can exercise the *live* code path — real HTTP, real chat
   completions, real retries — without a key or a GPU.
2. Anyone reviewing the harness can see exactly what the model is asked.

It is deliberately scripted, not clever: it returns the next reply from a list.
"""

from __future__ import annotations

import argparse
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Sequence


def make_handler(replies: Sequence[str]) -> type[BaseHTTPRequestHandler]:
    state = {"index": 0}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(length) or b"{}")
            self.server.last_request = body  # type: ignore[attr-defined]
            index = state["index"] % len(replies)
            reply = replies[index]
            state["index"] += 1
            payload: dict[str, Any] = {
                "id": "fake-1",
                "object": "chat.completion",
                "model": body.get("model", "fake"),
                "choices": [
                    {"index": 0, "message": {"role": "assistant", "content": reply}, "finish_reason": "stop"}
                ],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5},
            }
            data = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args: Any) -> None:
            pass

    return Handler


class FakeModel:
    """Context manager that serves ``replies`` on an ephemeral port."""

    def __init__(self, replies: Sequence[str]) -> None:
        self.replies = list(replies)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.replies))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> "FakeModel":
        self.thread.start()
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.server.shutdown()
        self.server.server_close()

    @property
    def base_url(self) -> str:
        host, port = self.server.server_address[:2]
        return f"http://{host}:{port}/v1"

    @property
    def requests(self) -> list[dict[str, Any]]:
        return [getattr(self.server, "last_request", {})]


def main() -> int:
    parser = argparse.ArgumentParser(description="Scripted OpenAI-compatible stub")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument(
        "--reply",
        action="append",
        default=[],
        help="one reply per turn; repeated calls reuse the last",
    )
    args = parser.parse_args()
    replies = args.reply or ['{"final": "ok"}']
    server = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(replies))
    print(f"serving on http://127.0.0.1:{args.port}/v1  model=fake", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())