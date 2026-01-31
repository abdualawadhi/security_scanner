#!/usr/bin/env python3
"""
Web Server Startup Script

Run this script to start the professional web frontend for the security scanner.

Usage:
    python run_server.py [--host HOST] [--port PORT] [--debug]
"""

import argparse
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from website_security_scanner.web.app import create_app, socketio


def main():
    parser = argparse.ArgumentParser(
        description='Low-Code Security Scanner Web Server'
    )
    parser.add_argument(
        '--host',
        default='0.0.0.0',
        help='Host to bind to (default: 0.0.0.0)'
    )
    parser.add_argument(
        '--port',
        type=int,
        default=5000,
        help='Port to bind to (default: 5000)'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Run in debug mode'
    )
    
    args = parser.parse_args()
    
    print(f"""
╔═══════════════════════════════════════════════════════════════╗
║     Low-Code Platform Security Scanner - Web Interface       ║
╠═══════════════════════════════════════════════════════════════╣
║  Server starting on: http://{args.host}:{args.port}{''.ljust(30 - len(args.host) - len(str(args.port)))}║
║  Debug mode: {'Enabled' if args.debug else 'Disabled'}{''.ljust(47 if args.debug else 46)}║
╚═══════════════════════════════════════════════════════════════╝

Press Ctrl+C to stop the server
""")
    
    # Create and run app
    app, socketio = create_app()
    socketio.run(
        app,
        host=args.host,
        port=args.port,
        debug=args.debug,
        allow_unsafe_werkzeug=True
    )


if __name__ == '__main__':
    main()
