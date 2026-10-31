'use strict';
const { spawnSync } = require('node:child_process');
const result = spawnSync('/workload/uring-helper', [], { encoding: 'utf8', timeout: 10000 });
if (result.error || result.signal) {
  console.error(result.error?.message || `helper terminated: ${result.signal}`);
  process.exit(70);
}
if (result.status !== 0) {
  process.stderr.write(result.stderr || 'io_uring helper failed\n');
  process.exit(result.status === 42 ? 42 : 70);
}
if (result.stdout.trim() !== 'sentrycheck-node-uring-verified') {
  console.error('io_uring readback assertion failed');
  process.exit(70);
}
console.log('sentrycheck-node-uring-ok');
