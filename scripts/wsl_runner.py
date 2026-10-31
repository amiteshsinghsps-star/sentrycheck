"""Run a Linux test executable produced by the Windows cross compiler."""
import os
import subprocess
import sys
from wsl_linker import linux_path

raise SystemExit(subprocess.call(["wsl", "-d", "Ubuntu", "--cd", linux_path(os.getcwd()), "--", linux_path(os.path.abspath(sys.argv[1])), *sys.argv[2:]]))
