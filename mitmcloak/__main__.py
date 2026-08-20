"""One-time setup: point mitmproxy's config at the addon, then get out of the way.

This never sits between the user and mitmproxy. It writes three lines of YAML and
exits, so mitmdump, mitmweb and the TUI all keep working exactly as they did.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import addon

CONFIG = Path.home() / ".mitmproxy" / "config.yaml"


def _addon_path() -> str:
    return str(Path(addon.__file__).resolve())


def _yaml():
    """mitmproxy ships ruamel.yaml, not PyYAML, and reads config.yaml with it."""
    from ruamel.yaml import YAML

    y = YAML(typ="safe", pure=True)
    y.default_flow_style = False
    return y


def _load(config: Path) -> dict:
    if not config.exists():
        return {}
    import io

    return _yaml().load(io.StringIO(config.read_text())) or {}


def _save(config: Path, data: dict) -> None:
    import io

    buf = io.StringIO()
    _yaml().dump(data, buf)
    config.write_text(buf.getvalue())


def install(preset: str | None, mode: str | None, config: Path) -> int:
    config.parent.mkdir(parents=True, exist_ok=True)
    data = _load(config)

    scripts = list(data.get("scripts") or [])
    path = _addon_path()
    if path not in scripts:
        scripts.append(path)
    data["scripts"] = scripts
    if preset:
        data["mitmcloak_preset"] = preset
    if mode:
        data["mitmcloak_mode"] = mode
    data.setdefault("connection_strategy", "lazy")

    _save(config, data)
    print(f"mitmcloak: wrote {config}")
    print(f"  scripts: {path}")
    print("\nPlain `mitmdump` now loads mitmcloak. No -s flag needed.")
    return 0


def uninstall(config: Path) -> int:
    if not config.exists():
        print(f"mitmcloak: {config} does not exist, nothing to do")
        return 0
    data = _load(config)
    path = _addon_path()
    scripts = [s for s in (data.get("scripts") or []) if s != path]
    if scripts:
        data["scripts"] = scripts
    else:
        data.pop("scripts", None)
    for key in ("mitmcloak_preset", "mitmcloak_mode"):
        data.pop(key, None)
    _save(config, data)
    print(f"mitmcloak: removed the addon from {config}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m mitmcloak")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_install = sub.add_parser("install", help="add mitmcloak to ~/.mitmproxy/config.yaml")
    p_install.add_argument("--preset", default=None)
    p_install.add_argument("--mode", default=None, choices=["auto", "static", "mirror"])
    p_install.add_argument("--config", default=str(CONFIG))

    p_uninstall = sub.add_parser("uninstall", help="remove it again")
    p_uninstall.add_argument("--config", default=str(CONFIG))

    sub.add_parser("path", help="print the addon path, for -s or config.yaml")

    args = parser.parse_args(argv)
    if args.cmd == "install":
        return install(args.preset, args.mode, Path(args.config))
    if args.cmd == "uninstall":
        return uninstall(Path(args.config))
    print(_addon_path())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
