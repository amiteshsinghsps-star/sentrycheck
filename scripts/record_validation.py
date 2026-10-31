"""Record bounded local observations, without inferring research accuracy."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--directory", action="append", help="Report directory relative to artifacts; repeat for multiple suites")
parser.add_argument("--output", type=Path, default=root / "docs/validation-summary.json")
parser.add_argument("--trace-replay", type=Path, help="Optional saved trace replay record; not new workload executions")
parser.add_argument("--builds", type=Path, help="Optional hash record for the tested binaries")
args = parser.parse_args()
rows = []
for directory in args.directory or ['live-validation', 'live-baselines', 'live-postgres']:
    for path in sorted((root / 'artifacts' / directory).glob('*.report.json')):
        raw = path.read_bytes()
        report = json.loads(raw)
        dynamic = report.get('dynamic') or {}
        rows.append({'case':path.stem.removesuffix('.report'), 'report':path.relative_to(root).as_posix(),
                     'report_sha256':'sha256:'+hashlib.sha256(raw).hexdigest(), 'scanned_at':report['scanned_at'], 'analyzer_version':report['sentrycheck_version'],
                     'image_digest':report['image_digest'], 'target_runtime':report['target_runtime'],
                     'status':report['status'], 'evidence_tier':dynamic.get('evidence_tier'), 'provenance':dynamic.get('provenance'),
                     'profile_sha256':dynamic.get('profile_sha256'), 'native_exits':[r['exit_code'] for r in dynamic.get('native', [])],
                     'sandbox_exits':[r['exit_code'] for r in dynamic.get('sandbox', [])], 'duration_ms':report['duration_ms'],
                     'finding_severities':sorted(set(f['severity'] for f in report['findings']))})
result = {'recorded_at':datetime.now(timezone.utc).isoformat(),
          'scope':'Actual profile-bounded local observations. Raw debug-build timings are uncontrolled; no production precision/recall claim.',
          'comparisons':rows, 'node_runtime':json.loads((root / 'artifacts/node-runtime/summary.json').read_text(encoding='utf-8'))}
if not rows:
    raise ValueError('No report observations found; refusing an empty validation record')
if args.trace_replay:
    raw = args.trace_replay.read_bytes()
    replay = json.loads(raw)
    result['trace_replay'] = {'record':args.trace_replay.as_posix(), 'record_sha256':'sha256:'+hashlib.sha256(raw).hexdigest(),
                              'scope':replay['scope'], 'status':replay['status'], 'trace_count':replay['trace_count'],
                              'event_count':sum(row['summary']['event_count'] for row in replay['traces']),
                              'parser_sha256':replay['parser_sha256']}
if args.builds:
    result['builds'] = json.loads(args.builds.read_text(encoding='utf-8'))
args.output.parent.mkdir(parents=True, exist_ok=True)
args.output.write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8', newline='\n')
print('Recorded', len(rows), 'live workload comparisons and the node-runtime test.')
