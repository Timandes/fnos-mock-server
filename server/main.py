"""fnOS Mock Server - Main application entry point."""

import argparse
import logging
import sys
from pathlib import Path

from fastapi import FastAPI, WebSocket
import uvicorn

from server.handlers import handle_websocket


def setup_logging(log_level: str) -> None:
    """Setup logging configuration.

    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR)
    """
    level = getattr(logging, log_level.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        stream=sys.stdout,
    )


def parse_args() -> argparse.Namespace:
    """Parse command line arguments.

    Returns:
        Parsed arguments
    """
    parser = argparse.ArgumentParser(
        description='fnOS Mock Server - Mock server for FeiNiu fnOS'
    )
    parser.add_argument(
        '-p', '--port',
        type=int,
        default=5666,
        help='WebSocket server port (default: 5666)'
    )
    parser.add_argument(
        '--host',
        type=str,
        default='0.0.0.0',
        help='Server host (default: 0.0.0.0)'
    )
    parser.add_argument(
        '--log-level',
        type=str,
        default='INFO',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        help='Log level (default: INFO)'
    )
    return parser.parse_args()


def create_app() -> FastAPI:
    """Create and configure FastAPI application.

    Returns:
        Configured FastAPI application
    """
    app = FastAPI(
        title='fnOS Mock Server',
        description='Mock server for FeiNiu fnOS to test pyfnos client',
        version='0.1.0',
    )

    @app.get('/')
    async def root() -> dict:
        """Root endpoint."""
        return {
            'message': 'fnOS Mock Server',
            'version': '0.1.0',
        }

    @app.websocket('/websocket')
    async def websocket_endpoint(websocket: WebSocket) -> None:
        """WebSocket endpoint for fnOS client connections."""
        await handle_websocket(websocket)

    return app


def main() -> None:
    """Main entry point."""
    args = parse_args()
    setup_logging(args.log_level)

    logger = logging.getLogger(__name__)
    logger.info(f'Starting fnOS Mock Server on {args.host}:{args.port}')

    app = create_app()

    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        log_level=args.log_level.lower(),
    )


if __name__ == '__main__':
    main()