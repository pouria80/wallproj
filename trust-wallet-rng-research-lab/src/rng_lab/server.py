"""Local-only entrypoint. Refuses non-loopback binds."""
import argparse

import uvicorn

from rng_lab.api import create_app


def main() -> None:
    ap = argparse.ArgumentParser(description="RNG Research Lab dashboard backend")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8756)
    ap.add_argument("--db", default=None)
    args = ap.parse_args()
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        raise SystemExit(f"refusing to bind {args.host}: local-only service "
                         "(use 127.0.0.1)")
    app = create_app(args.db)
    print(f"Trust Wallet RNG Research Lab backend: "
          f"http://{args.host}:{args.port}/api/docs")
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
