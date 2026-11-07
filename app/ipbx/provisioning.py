"""Phone auto-provisioning (Grandstream XML + Yealink cfg).

Two families the panel can fully auto-provision over HTTP:

    Grandstream (GXP/GRP):  http://SERVER:8080/provisioning/cfg<MAC>.xml
    Yealink (T/W series):   http://SERVER:8080/provisioning/<MAC>.cfg

The phone's MAC must be stored on the extension record in the panel.
Only minimal, well-documented parameters are emitted so every firmware
generation accepts the files:

    Grandstream  P47 : SIP server address      P35 : SIP user id
                 P36 : authenticate id         P37 : authenticate password
    Yealink      account.1.enable / label / display_name / user_name /
                 auth_name / password / sip_server_host / sip_server_port
                 (one format for the whole T2x/T3x/T4x desk line and the
                 W-series DECT bases)

Other brands (Fanvil, Htek, …) are deliberately NOT emitted — their
config formats change between firmware generations and a wrong file is
worse than none. Configure them manually with the SIP credentials the
extension page already shows.
"""
import re


def _mac_from(stem):
    """MAC from the file name WITHOUT its extension.

    The extension must be stripped first: '.cfg' contains the hex
    characters 'c' and 'f' and would corrupt the extraction.
    """
    hexdigits = re.sub(r"[^0-9a-f]", "", (stem or "").lower())
    if len(hexdigits) != 12:
        return None
    return hexdigits.upper()


def identify(filename):
    """Map a requested file name -> (brand, MAC) or (None, None).

    Grandstream phones ask for  cfg<mac>.xml, Yealink phones for
    <mac>.cfg. Anything else is unknown and must never be served —
    a phone receiving a foreign format silently misconfigures itself.
    """
    name = (filename or "").rsplit("/", 1)[-1].lower()
    if name.startswith("cfg") and name.endswith(".xml"):
        mac = _mac_from(name[3:-4])
        return ("grandstream", mac) if mac else (None, None)
    if name.endswith(".cfg"):
        mac = _mac_from(name[:-4])
        return ("yealink", mac) if mac else (None, None)
    return None, None


def _one_line(text):
    return " ".join(str(text or "").split())


def build_config(ext, server_ip):
    """Grandstream cfg<MAC>.xml body."""
    number = str(ext["ext"])
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<gs_provision version="1">\n'
        "  <config version=\"1\">\n"
        f"    <!-- ip-pbx-manager provisioning for extension {number} -->\n"
        f"    <P47>{_one_line(server_ip)}</P47>\n"
        f"    <P35>{number}</P35>\n"
        f"    <P36>{number}</P36>\n"
        f"    <P37>{_one_line(ext['secret'])}</P37>\n"
        "  </config>\n"
        "</gs_provision>\n"
    )
    return xml


def build_yealink_config(ext, server_ip):
    """Yealink <MAC>.cfg body (account 1, T2x/T3x/T4x/W bases)."""
    number = str(ext["ext"])
    lines = [
        "#!version:1.0.0.1",
        "account.1.enable = 1",
        f"account.1.label = {number}",
        f"account.1.display_name = {_one_line(ext.get('display_name') or number)}",
        f"account.1.user_name = {number}",
        f"account.1.auth_name = {number}",
        f"account.1.password = {_one_line(ext['secret'])}",
        f"account.1.sip_server_host = {_one_line(server_ip)}",
        "account.1.sip_server_port = 5060",
        "",
    ]
    return "\n".join(lines)


def provisioning_base_url(server_ip, port=8080):
    return f"http://{server_ip}:{port}/provisioning/"
