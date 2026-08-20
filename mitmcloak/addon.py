"""Stub addon, for `-s` and for the `scripts:` key in ~/.mitmproxy/config.yaml.

mitmproxy's script loader resolves file paths only, never module names, so the package
ships this file and `python -m mitmcloak install` points config.yaml at it.
"""
from mitmcloak import Bridge

addons = [Bridge()]
