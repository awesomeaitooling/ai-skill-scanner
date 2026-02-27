"""
Run this on a machine after the simulation to remove all artifacts.

    python cleanup.py

Removes:
  - The installed skills-scanner package
  - The sentinel file (prevents hook from re-firing)
  - Local build artifacts (build/, *.egg-info/)
"""
import os
import shutil
import subprocess
import sys
import tempfile


def run(label, *cmd):
    print(f"  {label}...", end=" ")
    result = subprocess.run(cmd, capture_output=True)
    if result.returncode == 0:
        print("done")
    else:
        print("skipped (not found)")


print("\n=== Simulation Cleanup ===\n")

# 1. Uninstall the package
run("Uninstalling skills-scanner", sys.executable, "-m", "pip", "uninstall", "-y", "skills-scanner")

# 2. Remove sentinel file
sentinel = os.path.join(tempfile.gettempdir(), ".skills_scanner_sim_ran")
print(f"  Removing sentinel file...", end=" ")
try:
    os.remove(sentinel)
    print("done")
except FileNotFoundError:
    print("skipped (not found)")

# 3. Remove build artifacts
for artifact in ["build", "skills_scanner.egg-info", "dist"]:
    path = os.path.join(os.path.dirname(__file__), artifact)
    print(f"  Removing {artifact}/...", end=" ")
    if os.path.exists(path):
        shutil.rmtree(path)
        print("done")
    else:
        print("skipped (not found)")

print("\nCleanup complete.\n")
