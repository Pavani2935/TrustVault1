"""Command line entry point (works the same on Windows, macOS and Linux).

    python -m trustvault serve           # production-grade WSGI server (waitress)
    python -m trustvault verify-audit    # verify the audit hash chain from the CLI
    python -m trustvault init-db         # create tables (also done automatically on start)
"""
from __future__ import annotations

import argparse
import logging
import os
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="trustvault")
    sub = parser.add_subparsers(dest="command", required=True)
    serve = sub.add_parser("serve", help="run the web server")
    serve.add_argument("--host", default=os.environ.get("HOST", "0.0.0.0"))
    serve.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8000")))
    serve.add_argument("--threads", type=int, default=int(os.environ.get("TRUSTVAULT_THREADS", "8")))
    sub.add_parser("verify-audit", help="verify the audit chain and print the head hash")
    sub.add_parser("init-db", help="create the schema and seed demo data if enabled")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    from . import create_app

    app = create_app()
    tv = app.extensions["trustvault"]

    if args.command == "serve":
        from waitress import serve as waitress_serve

        print(f"TrustVault listening on http://{'127.0.0.1' if args.host == '0.0.0.0' else args.host}:{args.port}",
              flush=True)
        waitress_serve(app, host=args.host, port=args.port, threads=args.threads,
                       ident="TrustVault", clear_untrusted_proxy_headers=False,
                       max_request_body_size=(tv["settings"].max_upload_mb + 2) * 1024 * 1024)
        return 0
    if args.command == "verify-audit":
        conn = tv["db"].connect()
        try:
            result = tv["audit"].verify_chain(conn)
        finally:
            conn.close()
        print(result)
        return 0 if result["ok"] else 2
    if args.command == "init-db":
        print("Schema ready:", tv["db"].describe())
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
