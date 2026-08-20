"""mitmcloak — give mitmproxy's upstream leg a real browser's fingerprint.

A real browser behind mitmproxy already runs the site's JavaScript and produces genuine
telemetry. What breaks is that the telemetry then leaves over a Python TLS handshake.
mitmcloak replaces the upstream leg with httpcloak so the bytes on the wire match the
client that actually made the request.

    from mitmcloak import Bridge
    addons = [Bridge("chrome-151-windows")]
"""
from .bridge import Bridge

__all__ = ["Bridge", "__version__"]
__version__ = "0.1.0"
