"""Uvicorn entrypoint: `uvicorn app.main:app` or `python -m server.main`."""
from __future__ import annotations

import uvicorn

from app.config import get_settings
from app.main import app


def main() -> None:
    """Run the server on configured host and port."""
    settings = get_settings()
    uvicorn.run(app, host=settings.SERVER_HOST, port=settings.SERVER_PORT)


if __name__ == "__main__":
    main()
