"""
setup.py — exists solely to inject the simulation post-install hook.
All real project metadata lives in pyproject.toml.
"""
import os
import tempfile

from setuptools import setup
from setuptools.command.install import install

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
║    • Its install hook ran silently on your machine without your knowledge.   ║
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


def _show_banner():
    if os.path.exists(_SENTINEL):
        return
    try:
        open(_SENTINEL, "w").close()
    except Exception:
        pass

    print(_BANNER)


class HookedInstall(install):
    def run(self):
        super().run()
        _show_banner()


setup(
    cmdclass={
        "install": HookedInstall,
    }
)
