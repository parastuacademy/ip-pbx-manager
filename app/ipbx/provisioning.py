"""Grandstream auto-provisioning (XML configuration files).

Grandstream phones fetch  cfg<MAC>.xml  from the configured provisioning
server (HTTP). We serve them from the panel:

    http://SERVER-IP:8080/provisioning/cfgAABBCCDDEEFF.xml

The phone's MAC must be stored on the extension record in the panel.
Only the minimal, well-documented Grandstream parameters are emitted so
every GXP/GRP firmware generation accepts the file:

    P47 : SIP server address              (account 1)
    P35 : SIP user id                     (account 1)
    P36 : authenticate id                 (account 1)
    P37 : authenticate password           (account 1)
"""
import re


def parse_mac(filename):
    """Extract a 12-hex-digit MAC from names like cfgaabbccddeeff.xml."""
    if not filename:
        return None
    hexdigits = re.sub(r"[^0-9a-fA-F]", "", filename.split("/")[-1])
    if len(hexdigits) < 12:
        return None
    return hexdigits[-12:].upper()


def build_config(ext, server_ip):
    number = str(ext["ext"])
    secret = str(ext["secret"])
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<gs_provision version="1">\n'
        "  <config version=\"1\">\n"
        f"    <!-- ip-pbx-manager provisioning for extension {number} -->\n"
        f"    <P47>{server_ip}</P47>\n"
        f"    <P35>{number}</P35>\n"
        f"    <P36>{number}</P36>\n"
        f"    <P37>{secret}</P37>\n"
        "  </config>\n"
        "</gs_provision>\n"
    )
    return xml


def provisioning_base_url(server_ip, port=8080):
    return f"http://{server_ip}:{port}/provisioning/"
