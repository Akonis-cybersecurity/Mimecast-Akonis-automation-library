#!/usr/bin/env python3
"""
scripts/test_action_live.py — Test MimecastBlockSender against the real API.

Never sends events to Sekoia.IO.  Reads credentials from a .env file only.
Calls action.run() directly — no Docker, no /symphony/module_configuration.

Usage (run from the Mimecast-Akonis/ directory):
    python scripts/test_action_live.py
    python scripts/test_action_live.py --env /path/to/.env
    python scripts/test_action_live.py --sender spammer@evil.com
    python scripts/test_action_live.py --sender spammer@evil.com --to victim@corp.com

Expected .env keys:
    MIMECAST_CLIENT_ID       OAuth2 client ID  — required
    MIMECAST_CLIENT_SECRET   OAuth2 client secret — required
    MIMECAST_BASE_URL        API base URL — default https://api.services.mimecast.com
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Dict, Optional

# ---------------------------------------------------------------------------
# sys.path — make mimecast_modules importable when run from Mimecast-Akonis/
# ---------------------------------------------------------------------------

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_MODULE_ROOT = os.path.dirname(_SCRIPT_DIR)
if _MODULE_ROOT not in sys.path:
    sys.path.insert(0, _MODULE_ROOT)

try:
    from mimecast_modules import MimecastModule
    from mimecast_modules.actions.action_block_sender import MimecastBlockSender
    from mimecast_modules.client.errors import MimecastAPIError, MimecastAuthError, MimecastRateLimitError
    from mimecast_modules.models import MimecastModuleConfiguration
except ImportError as exc:
    sys.exit(
        f"Cannot import mimecast_modules: {exc}\n"
        "Run the script from the Mimecast-Akonis/ directory:\n"
        "  python scripts/test_action_live.py"
    )

# ---------------------------------------------------------------------------
# Terminal colours
# ---------------------------------------------------------------------------

_USE_COLOUR = sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _USE_COLOUR else text


def green(t: str) -> str:
    return _c("32", t)


def red(t: str) -> str:
    return _c("31", t)


def bold(t: str) -> str:
    return _c("1", t)


def dim(t: str) -> str:
    return _c("2", t)


# ---------------------------------------------------------------------------
# .env loader (no external dependency)
# ---------------------------------------------------------------------------


def _load_env_file(path: str) -> Dict[str, str]:
    env: Dict[str, str] = {}
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
                value = value[1:-1]
            env[key] = value
    return env


def load_env(path: Optional[str] = None) -> None:
    candidates = []
    if path:
        candidates.append(path)
    candidates += [
        os.path.join(os.getcwd(), ".env"),
        os.path.join(_MODULE_ROOT, ".env"),
        os.path.join(_SCRIPT_DIR, ".env"),
    ]
    for candidate in candidates:
        if os.path.isfile(candidate):
            os.environ.update(_load_env_file(candidate))
            print(dim(f"Loaded .env from {candidate}"))
            return
    print(dim("No .env file found — using existing environment variables"))


def _require(key: str) -> str:
    value = os.environ.get(key, "").strip()
    if not value:
        sys.exit(f"Missing required environment variable: {key}")
    return value


def _optional(key: str, default: str = "") -> str:
    return os.environ.get(key, default).strip()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Live test for MimecastBlockSender — never sends to Sekoia.IO.",
    )
    parser.add_argument("--env", metavar="FILE", help="Path to .env file")
    parser.add_argument(
        "--sender",
        default="test-block@spamexample.com",
        help="Sender email to block (default: test-block@spamexample.com)",
    )
    parser.add_argument(
        "--to",
        default=None,
        metavar="EMAIL",
        help="Restrict the block to this recipient (default: everyone)",
    )
    parser.add_argument(
        "--description",
        default="Test block via Sekoia POC",
        help="Policy description",
    )
    args = parser.parse_args()

    load_env(args.env)

    base_url = _optional("MIMECAST_BASE_URL", "https://api.services.mimecast.com")
    client_id = _require("MIMECAST_CLIENT_ID")
    _require("MIMECAST_CLIENT_SECRET")  # presence check only — never printed

    print(f"\n{'=' * 60}")
    print(f"  Mimecast BlockSender — Live Action Test")
    print(f"{'=' * 60}")
    print(f"  Base URL : {base_url}")
    print(f"  Sender   : {args.sender}")
    print(f"  To       : {args.to or '(everyone)'}")
    print(f"  Desc     : {args.description}")
    print()

    # ------------------------------------------------------------------
    # Build module + action — no Docker, no file-based configuration.
    # Setting module.configuration directly bypasses the SDK file loader.
    # action.run() is called instead of action.execute() so no argument
    # file is needed either.
    # ------------------------------------------------------------------

    module = MimecastModule()
    module.configuration = MimecastModuleConfiguration(
        client_id=client_id,
        client_secret=_optional("MIMECAST_CLIENT_SECRET"),
        base_url=base_url,
    )

    action = MimecastBlockSender(module=module)

    action_args: dict = {
        "sender_email": args.sender,
        "description": args.description,
    }
    if args.to:
        action_args["to_email"] = args.to

    print(f"  {bold('[ ACTION ]')} MimecastBlockSender")
    print(f"  {dim('Calling POST /policy-management/cloud-gateway/v1/blocked-senders/policies ...')}")

    try:
        result = action.run(action_args)
    except MimecastAuthError as exc:
        print(f"  {red('✗ AUTH ERROR')} — {exc}")
        sys.exit(1)
    except MimecastRateLimitError as exc:
        print(f"  {red('✗ RATE LIMIT')} — {exc}")
        sys.exit(1)
    except MimecastAPIError as exc:
        print(f"  {red('✗ API ERROR')} — {exc}")
        sys.exit(1)
    except Exception as exc:
        print(f"  {red(f'✗ ERROR ({type(exc).__name__})')} — {exc}")
        sys.exit(1)

    print(f"  {green('✓ SUCCESS')}\n")
    print(bold("Result:"))
    print(json.dumps(result, indent=2))
    print()
    print(dim("→ Check the Mimecast console: Policy Management > Blocked Senders"))


if __name__ == "__main__":
    main()
