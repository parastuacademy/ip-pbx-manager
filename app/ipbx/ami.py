"""Minimal Asterisk Manager Interface (AMI) client.

The panel opens a short-lived AMI connection per status/apply request.
Everything goes through the `Command` action with text parsing — simple,
version-tolerant, and enough for this product. Port 5038 is only reachable
on the internal docker network; it is never published.
"""
import os
import re
import socket


class AMIError(Exception):
    pass


class AMIClient:
    def __init__(self, host=None, port=5038, username="panel", password=None):
        self.host = host or os.environ.get("AMI_HOST", "localhost")
        self.port = int(port)
        self.username = username
        self.password = password or os.environ.get("AMI_PASSWORD", "ipbx-ami-change-me")
        self.sock = None
        self._id = 0

    # ------------------------------------------------------------ lifecycle
    def __enter__(self):
        try:
            self.sock = socket.create_connection((self.host, self.port), timeout=5)
        except OSError as exc:
            raise AMIError(f"cannot connect to AMI {self.host}:{self.port} ({exc})") from exc
        self.sock.settimeout(6)
        try:
            banner = self._read_packet()
            if "Asterisk Call Manager" not in banner:
                raise AMIError("unexpected AMI banner")
            resp = self._send_action({"Action": "Login",
                                      "Username": self.username,
                                      "Secret": self.password})
            if "Response: Success" not in resp:
                raise AMIError("AMI login rejected (check AMI_PASSWORD)")
        except AMIError:
            self._close()
            raise
        return self

    def __exit__(self, *exc):
        self._close()
        return False

    def _close(self):
        if self.sock:
            try:
                self.sock.sendall(b"Action: Logoff\r\n\r\n")
            except OSError:
                pass
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    # -------------------------------------------------------------- plumbing
    def _read_packet(self):
        buf = b""
        while b"\r\n\r\n" not in buf:
            try:
                data = self.sock.recv(8192)
            except (OSError, socket.timeout) as exc:
                raise AMIError(f"AMI read failed ({exc})") from exc
            if not data:
                raise AMIError("AMI connection closed")
            buf += data
        pkt, rest = buf.split(b"\r\n\r\n", 1)
        self._rest = rest
        return pkt.decode("utf-8", "replace")

    def _send_action(self, fields):
        self._id += 1
        aid = f"ipbx{self._id}"
        lines = [f"ActionID: {aid}"] + [f"{k}: {v}" for k, v in fields.items()]
        payload = ("\r\n".join(lines) + "\r\n\r\n").encode()
        self.sock.sendall(payload)
        # Read packets until one carries our ActionID (skip async events)
        pkt = self._read_packet()
        seen = pkt
        for _ in range(50):
            if f"ActionID: {aid}" in seen or seen.startswith("Response: Error"):
                return seen
            seen = self._read_packet()
        raise AMIError("AMI response timeout")

    # --------------------------------------------------------------- public
    def command(self, cmd):
        """Run an Asterisk CLI command and return its text output."""
        self._id += 1
        aid = f"ipbx{self._id}"
        lines = [f"ActionID: {aid}", "Action: Command", f"Command: {cmd}"]
        self.sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())

        buf = self._read_packet()
        if "Response: Error" in buf.split("\r\n")[0]:
            raise AMIError(buf.strip())
        # "Response: Follows" ... output ... "--END COMMAND--"
        guard = 0
        while "--END COMMAND--" not in buf:
            buf += "\r\n" + self._read_packet()
            guard += 1
            if guard > 500 or len(buf) > 1_000_000:
                raise AMIError("AMI command output too large")
        marker = f"ActionID: {aid}\r\n"
        idx = buf.find(marker)
        out = buf[idx + len(marker):] if idx >= 0 else buf
        return out.split("--END COMMAND--")[0].strip("\r\n")

    # ------------------------------------------------------------ operations
    def reload_all(self):
        self.command("pjsip reload")
        self.command("dialplan reload")
        self.command("voicemail reload")

    def db_put_record(self, ext, value="1"):
        self.command(f"database put rec {ext} {value}")

    def db_del_record(self, ext):
        try:
            self.command(f"database del rec {ext}")
        except AMIError:
            pass  # already absent

    def db_put_vm(self, ext, value="1"):
        self.command(f"database put vm {ext} {value}")

    def db_del_vm(self, ext):
        try:
            self.command(f"database del vm {ext}")
        except AMIError:
            pass  # already absent

    def trunk_registered(self):
        out = self.command("pjsip show registrations")
        for line in out.splitlines():
            if "pishgaman" in line and "Registered" in line:
                return True
        return False

    def online_extensions(self):
        """Return the set of extension numbers with an available contact."""
        out = self.command("pjsip show contacts")
        online = set()
        for line in out.splitlines():
            if "Contact:" not in line:
                continue
            m = re.search(r"<([A-Za-z0-9_]+)/", line)
            if not m:
                continue
            if re.search(r"\b(Avail|Qualified)\b", line):
                online.add(m.group(1))
        return online

    def active_channels(self):
        out = self.command("core show channels concise")
        names = []
        for line in out.splitlines():
            if line.strip() and "!" in line and "PJSIP" in line:
                names.append(line.split("!", 1)[0])
        return names


def try_client():
    """Context-manager shortcut; raises AMIError when Asterisk is unreachable."""
    return AMIClient()
