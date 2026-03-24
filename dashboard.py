"""
Standalone launcher for the 4SSH_CONTROL monitoring dashboard.
Run alongside bastion.py — they share the same SQLite audit database.
"""

import argparse

import uvicorn

from ai_defense.core.audit import AuditLogger
from ai_defense.core.config import load_config
from ai_defense.web.dashboard import create_app


def main() -> None:
    parser = argparse.ArgumentParser(description="4SSH_CONTROL Dashboard")
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--host", default="")
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args()

    cfg = load_config(args.config)
    host = args.host or cfg.dashboard.host
    port = args.port or cfg.dashboard.port

    audit = AuditLogger(cfg.audit)
    app = create_app(audit)

    print(f"\n  Dashboard: http://{host}:{port}\n")
    uvicorn.run(app, host=host, port=port, log_level="warning")


if __name__ == "__main__":
    main()
