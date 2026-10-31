"""Use Ubuntu's gcc as the linker for Windows Rust's Linux cross target."""
import os
import re
import shlex
import subprocess
import sys
import tempfile

def linux_path(value):
    normalized = value.replace("\\", "/")
    for prefix in ("//wsl.localhost/Ubuntu/", "//wsl$/Ubuntu/"):
        if normalized.lower().startswith(prefix.lower()):
            return "/" + normalized[len(prefix):]
    if re.match(r"^[A-Za-z]:[\\/]", value):
        return "/mnt/" + value[0].lower() + "/" + value[3:].replace("\\", "/")
    return value

def main():
    raw_args = []
    for argument in sys.argv[1:]:
        if argument.startswith("@"):
            with open(argument[1:], "rb") as response:
                raw = response.read()
            text = raw.decode("utf-16" if raw.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8")
            raw_args.extend(shlex.split(text))
        else:
            raw_args.append(argument)
    args = []
    for argument in raw_args:
        if argument.startswith("-L") and (re.match(r"^-L[A-Za-z]:", argument) or argument[2:].startswith(("\\\\", "//"))):
            argument = "-L" + linux_path(argument[2:])
        else:
            argument = linux_path(argument)
        args.append(argument)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", suffix=".rsp", dir=os.getcwd(), delete=False) as response:
        response.write("\n".join(shlex.quote(argument) for argument in args))
        response_path = response.name
    try:
        return subprocess.call(["wsl", "-d", "Ubuntu", "--cd", linux_path(os.getcwd()), "--", "gcc", "@" + linux_path(response_path)])
    finally:
        os.unlink(response_path)

if __name__ == "__main__":
    raise SystemExit(main())
