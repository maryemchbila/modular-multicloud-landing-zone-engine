"""Entrypoint local de la plateforme Web J3."""

from __future__ import annotations

import sys


LISTEN_ADDRESS = "127.0.0.1"
PORT = 5000


def main() -> int:
    try:
        from web import create_app
    except ModuleNotFoundError as exc:
        print(
            f"Web dependency missing: {exc.name}. "
            "Run from python-engine: python -m pip install -r ..\\requirements.txt",
            file=sys.stderr,
        )
        return 1
    try:
        app = create_app()
    except ValueError as exc:
        print(f"Web startup failed: {exc}", file=sys.stderr)
        return 1
    print(f"LISTEN_ADDRESS={LISTEN_ADDRESS}")
    print(f"PORT={PORT}")
    print(f"http://{LISTEN_ADDRESS}:{PORT}")
    app.run(host=LISTEN_ADDRESS, port=PORT, debug=False, use_reloader=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
