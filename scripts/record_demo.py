"""Record actual command output as an asciicast v2, with optional phase markers.

This is a timed pipe capture, not a reenactment or a PTY emulator. LF is converted
to CRLF only in the terminal-playback stream; original decoded text is in JSONL.
"""
import argparse
import codecs
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


def digest(path):
    return "sha256:" + hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--events", type=Path, required=True)
    parser.add_argument("--start-marker")
    parser.add_argument("--stop-marker")
    parser.add_argument("--title", default="SENTRYCHECK real node-runtime checks")
    parser.add_argument("--width", type=int, default=120)
    parser.add_argument("--height", type=int, default=36)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("a command is required after --")
    if args.width < 20 or args.height < 5:
        parser.error("terminal dimensions are too small")
    metadata = args.output.with_suffix(args.output.suffix + ".metadata.json")
    if any(path.exists() for path in [args.output, args.events, metadata]):
        parser.error("recording files must be new; previous evidence is never overwritten")
    for path in [args.output, args.events, metadata]:
        path.parent.mkdir(parents=True, exist_ok=True)
    started_wall = datetime.now(timezone.utc)
    started = time.monotonic()
    capture_start = None if args.start_marker else started
    capture_stop = None
    emitted = 0
    header_written = False
    process = None
    exit_code = 2
    summary = {"schema_version": "1.0", "status": "running", "command": command,
               "started_at": started_wall.isoformat(), "recording_kind": "actual-command-pipe-output",
               "record_script_sha256": digest(__file__), "start_marker": args.start_marker, "stop_marker": args.stop_marker,
               "note": "No generated/replayed terminal content. Playback normalizes line endings; JSONL preserves original decoded text. Elapsed timestamps include actual waits."}
    metadata.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8", newline="\n")
    def interrupt(_signal, _frame):
        raise KeyboardInterrupt("recording interrupted")
    signal.signal(signal.SIGTERM, interrupt)
    with args.output.open("x", encoding="utf-8") as cast, args.events.open("x", encoding="utf-8") as events:
        header = {"version": 2, "width": args.width, "height": args.height, "timestamp": int(started_wall.timestamp()),
                  "title": args.title, "env": {"TERM": "xterm-256color"}}
        def emit(text):
            nonlocal capture_start, capture_stop, emitted, header_written
            observed = time.monotonic()
            if args.start_marker and args.start_marker in text and capture_start is None:
                capture_start = observed
                summary["capture_started_at"] = datetime.now(timezone.utc).isoformat()
            if capture_start is not None and capture_stop is None:
                if not header_written:
                    if args.start_marker:
                        header["timestamp"] = int(time.time())
                    cast.write(json.dumps(header) + "\n")
                    header_written = True
                elapsed = observed - capture_start
                original = {"elapsed_seconds": elapsed, "observed_at": datetime.now(timezone.utc).isoformat(), "stream": "combined-stdout-stderr", "text": text}
                events.write(json.dumps(original, ensure_ascii=False) + "\n")
                display = text.replace("\r\n", "\n").replace("\n", "\r\n")
                cast.write(json.dumps([round(elapsed, 6), "o", display], ensure_ascii=False) + "\n")
                cast.flush()
                events.flush()
                emitted += 1
                if args.stop_marker and args.stop_marker in text:
                    capture_stop = observed

        decoder = codecs.getincrementaldecoder("utf-8")("replace")
        pending = ""
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)
            while True:
                block = os.read(process.stdout.fileno(), 4096)
                if not block:
                    break
                sys.stdout.buffer.write(block)
                sys.stdout.buffer.flush()
                pending += decoder.decode(block)
                while "\n" in pending:
                    line, pending = pending.split("\n", 1)
                    emit(line + "\n")
                if len(pending) > 65536:
                    emit(pending)
                    pending = ""
            pending += decoder.decode(b"", final=True)
            if pending:
                emit(pending)
            exit_code = process.wait()
        except (OSError, KeyboardInterrupt) as error:
            summary["error"] = str(error) or type(error).__name__
            if process is not None and process.poll() is None:
                # Let the wrapped script run its existing EXIT cleanup trap.
                process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=45)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        finally:
            if process is not None and process.stdout is not None:
                process.stdout.close()
            summary["command_exit_code"] = exit_code
            summary["events_recorded"] = emitted
            summary["capture_elapsed_seconds"] = ((capture_stop or time.monotonic()) - capture_start) if capture_start is not None else None
            summary["finished_at"] = datetime.now(timezone.utc).isoformat()
            complete = exit_code == 0 and emitted > 0 and (not args.stop_marker or capture_stop is not None)
            summary["status"] = "complete" if complete else "failed"
            if not header_written:
                cast.write(json.dumps(header) + "\n")
            cast.flush()
            events.flush()
    summary["asciicast_sha256"] = digest(args.output)
    summary["events_sha256"] = digest(args.events)
    metadata.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"Recorded {emitted} actual output events: {args.output} ({summary['status']})", flush=True)
    return 0 if summary["status"] == "complete" else 2


if __name__ == "__main__":
    raise SystemExit(main())
