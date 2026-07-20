"""Entrypoint script for running HYDRA Admin Bot from systemd or CLI."""
import sys
from pathlib import Path

# Bootstrap project import path
_PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from hydra.core.state import load_state
from hydra.services.telegram.bot import run_admin_bot


def main():
    state = load_state()
    token = getattr(state.telegram, "admin_token", "").strip()
    chat_id = getattr(state.telegram, "admin_chat_id", "").strip()
    if not token or not chat_id:
        sys.stderr.write("[HYDRA Admin Bot Error] admin_token or admin_chat_id is missing in state.\n")
        sys.exit(1)
    run_admin_bot(token, chat_id)


if __name__ == "__main__":
    main()
