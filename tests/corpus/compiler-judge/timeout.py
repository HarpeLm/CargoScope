"""timeout.py SECONDS COMMAND...: runs COMMAND, kills it after SECONDS (exit 124)."""
import subprocess, sys
try:
    sys.exit(subprocess.run(sys.argv[2:], timeout=float(sys.argv[1])).returncode)
except subprocess.TimeoutExpired:
    sys.exit(124)
