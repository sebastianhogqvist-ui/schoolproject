"""Uvicorn entrypoint: `uvicorn app.main:app` or `python -m server.main`."""
from __future__ import annotations

import uvicorn

from app.main import app


def main() -> None:
    """Run the server on 0.0.0.0:8080."""
    uvicorn.run(app, host="0.0.0.0", port=8080)


if __name__ == "__main__":
    main()
