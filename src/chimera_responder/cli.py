"""``chimera-responder`` entry point."""

from __future__ import annotations

import logging
import sys

from chimera_responder.config import ResponderSettings


def main() -> None:
    import uvicorn

    from chimera_responder.app import create_app

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s", stream=sys.stderr)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    s = ResponderSettings.from_env()
    print(f"Chimera responder on {s.host}:{s.port} (mode={s.mode}, actions={','.join(s.actions)})", file=sys.stderr)
    uvicorn.run(create_app(s), host=s.host, port=s.port, log_level="warning", server_header=False)


if __name__ == "__main__":
    main()
