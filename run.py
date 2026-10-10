"""Entry point for the Network Intrusion Detection and Threat Monitoring System.

Starts the read-only dashboard and JSON API on localhost. Live packet capture
is intentionally not started here: the dashboard only displays data already in
the SQLite database. Run from the project root:

    .venv/bin/python run.py
"""

from nids.api import create_app
from nids.config import ConfigError, load_config

HOST = "127.0.0.1"
PORT = 5000


def build_app(db_path=None):
    """Load configuration and build the Flask application."""
    return create_app(config=load_config(), db_path=db_path)


def main():
    try:
        app = build_app()
    except ConfigError as error:
        print(f"Configuration error: {error}")
        return 1

    print(f"Network Intrusion Detection dashboard: http://{HOST}:{PORT}/")
    print("Press Ctrl+C to stop. Live packet capture is not started.")
    app.run(host=HOST, port=PORT, debug=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
