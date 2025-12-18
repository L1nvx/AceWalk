SCRIPT_VERSION = "0.2.0"

try:
    from impacket import version as impacket_version

    IMPACKET_VERSION = getattr(impacket_version, "BANNER", "impacket (unknown)")
except Exception:
    IMPACKET_VERSION = "impacket (not available)"

BANNER = f"""AceWalk {SCRIPT_VERSION} | {IMPACKET_VERSION}"""
