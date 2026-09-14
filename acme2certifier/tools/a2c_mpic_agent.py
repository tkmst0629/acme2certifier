#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Run the MPIC remote validation agent (development server).

For production, serve ``acme2certifier.acme_srv.challenge_validators.mpic.
agent_wsgi:application`` behind a real WSGI server (uWSGI/gunicorn) with mutual
TLS terminated at the reverse proxy. See docs/mpic.md.
"""

import argparse


def main() -> None:
    """CLI entry point for the MPIC agent dev server."""
    parser = argparse.ArgumentParser(description="acme2certifier MPIC agent")
    parser.add_argument("--host", default="0.0.0.0", help="bind address")
    parser.add_argument("--port", type=int, default=8443, help="bind port")
    args = parser.parse_args()

    # Imported here so --help works without loading the app configuration.
    # pylint: disable=import-outside-toplevel
    from acme2certifier.acme_srv.challenge_validators.mpic import agent_wsgi

    agent_wsgi.run(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
