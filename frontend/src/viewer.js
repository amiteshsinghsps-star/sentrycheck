(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const array = (value) => Array.isArray(value) ? value : [];
  const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
  const text = (value, fallback = 'Not available') => typeof value === 'string' && value.length ? value : fallback;
  const number = (value) => typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : null;
  const count = (value) => number(value) === null ? '—' : value.toLocaleString('en-US');
  const short = (value, max = 28) => typeof value === 'string' && value.length > max ? `${value.slice(0, max - 8)}…${value.slice(-7)}` : text(value);
  const human = (value) => text(value).replace(/^gap-/, '').replaceAll('-', ' ').replaceAll('_', ' ').replace(/^./, (c) => c.toUpperCase());
  const fmtMs = (value) => number(value) === null ? 'Not available' : value >= 1000 ? `${(value / 1000).toFixed(2)} s` : `${value} ms`;
  const paths = {
    grid: ['M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z'],
    flag: ['M5 21V3', 'M5 4h13l-3 5 3 5H5'],
    book: ['M12 5v16M12 5C8 2 4 3 2 4v15c4-2 7-1 10 2 3-3 6-4 10-2V4c-2-1-6-2-10 1Z'],
    trace: ['M4 4v16h17M8 14h3M8 9h8M14 14h6'],
    search: ['M20 20l-5-5', 'M17 10a7 7 0 1 1-14 0 7 7 0 0 1 14 0'],
    arrow: ['M5 12h14m-5-5 5 5-5 5'],
    shield: ['M12 2 3 6v6c0 6 9 10 9 10s9-4 9-10V6l-9-4Z', 'm8 12 3 3 5-6'],
    clock: ['M22 12a10 10 0 1 1-20 0 10 10 0 0 1 20 0', 'M12 6v6l4 2'],
    cube: ['m12 2 9 5v10l-9 5-9-5V7l9-5ZM3 7l9 5 9-5M12 12v10'],
    external: ['M14 3h7v7m0-7-10 10M10 3H3v18h18v-7'],
    info: ['M22 12a10 10 0 1 1-20 0 10 10 0 0 1 20 0', 'M12 11v6M12 7v1'],
  };
  function icon(name) {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    for (const [key, value] of Object.entries({ viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': '1.5', 'stroke-linecap': 'round', 'stroke-linejoin': 'round', class: 'icon', 'aria-hidden': 'true' })) svg.setAttribute(key, value);
    for (const d of paths[name] || paths.info) { const p = document.createElementNS('http://www.w3.org/2000/svg', 'path'); p.setAttribute('d', d); svg.append(p); }
    return svg;
  }
  function el(tag, attrs = {}, ...children) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs)) {
      if (value === undefined || value === null || value === false) continue;
      if (key === 'class') node.className = value;
      else if (key.startsWith('on')) node.addEventListener(key.slice(2), value);
      else if (key === 'disabled' || key === 'hidden') node[key] = value;
      else node.setAttribute(key, String(value));
    }
    for (const child of children.flat(Infinity)) if (child !== undefined && child !== null && child !== false) node.append(child instanceof Node ? child : document.createTextNode(String(child)));
    return node;
  }
  const button = (label, fn, kind = '') => el('button', { class: `button ${kind}`, type: 'button', onclick: fn }, label);
  const link = (label, hash, kind = '') => el('a', { href: hash, class: kind }, label);
  const tone = (severity) => severity === 'hard-failure' || severity === 'silent-degradation' ? 'red' : severity === 'full' ? 'teal' : severity === 'unknown' ? 'gray' : 'amber';
  const badge = (label, color = 'gray') => el('span', { class: `badge badge-${color}` }, el('i', { class: 'badge-dot' }), label);
  const tierBadge = (tier) => badge(text(tier, 'static-only'), tier === 'dynamic-runsc-diff' || tier === 'dynamic-kata-diff' ? 'diff' : tier === 'dynamic-native-only' ? 'native' : 'amber');
  function external(label, url, className = '') {
    try {
      const parsed = new URL(url);
      if (parsed.protocol === 'https:' || parsed.protocol === 'http:') return el('a', { href: parsed.href, target: '_blank', rel: 'noopener noreferrer', class: className }, label, icon('external'));
    } catch { /* Only absolute HTTP(S) citations become links. */ }
    return el('span', { class: className }, label, el('span', { class: 'source-label' }, 'Source URL unavailable or unsupported'));
  }
  function definitions(rows) {
    return el('dl', { class: 'definition-list' }, rows.map(([label, value, mono = false]) => el('div', { class: 'definition-row' }, el('dt', {}, label), el('dd', { class: mono ? 'mono' : '' }, value))));
  }
  function panel(title, body, action = null, caption = null) {
    return el('section', { class: 'panel' }, el('div', { class: 'panel-header' }, el('div', { class: 'panel-heading' }, el('h2', {}, title)), action), body, caption ? el('div', { class: 'panel-note' }, caption) : null);
  }
  const body = (...children) => el('div', { class: 'panel-body' }, children);
  function empty(title, description) { return el('div', { class: 'empty-state' }, icon('search'), el('h2', {}, title), el('p', {}, description)); }
  function hashRow(label, value) { return el('div', { class: 'hash-row' }, el('div', { class: 'uppercase' }, label), el('code', {}, text(value))); }
  function bulletList(items) { return el('ul', { class: 'bullet-list' }, items.map((item) => el('li', {}, text(item)))); }

  const state = { payload: null, report: null, kb: null, availableKb: null, matrix: null, selectedRuntime: 'gvisor', demo: false, source: '', error: null, findingTab: 'findings', findingQuery: '', findingSeverity: '', findingPage: 0, kbTab: 'gaps', kbQuery: '', kbStatus: '', kbPage: 0, tracePage: 0, selectedRun: 0, syscallPage: 0, sarifRun: 0 };
  const PAGE = 20;
  function requireCondition(ok, message) { if (!ok) throw new Error(message); }
  const validDigest = (value) => typeof value === 'string' && /^sha256:[a-f0-9]{64}$/.test(value);
  const normalizedVersion = (value) => typeof value === 'string' ? value.trim().replace(/^(release-)+/, '') : '';
  function checkTarget(target) {
    requireCondition(object(target) && ['gvisor', 'kata'].includes(target.name) && typeof target.version === 'string' && target.version.length > 0 && ['amd64', 'arm64', '386'].includes(target.architecture), 'Target runtime must include a supported name, version and architecture.');
  }
  function checkTier(tier, target, allowStatic = false) {
    requireCondition(['dynamic-native-only', 'dynamic-runsc-diff', 'dynamic-kata-diff', ...(allowStatic ? ['static-only'] : [])].includes(tier), 'Evidence tier is not recognized.');
    requireCondition((tier !== 'dynamic-runsc-diff' || target.name === 'gvisor') && (tier !== 'dynamic-kata-diff' || target.name === 'kata'), 'Evidence tier contradicts its target runtime.');
  }
  function checkClassification(severity, failureClass, tier, target, level = null) {
    const classes = { 'hard-failure': ['F1', 'error'], 'silent-degradation': ['F2', 'warning'], 'performance-regression': ['F3', 'warning'], 'compatibility-risk': ['unconfirmed', 'note'] };
    const expected = classes[severity];
    requireCondition(expected && failureClass === expected[0] && (level === null || level === expected[1]), 'Finding severity contradicts its classification.');
    checkTier(tier, target);
    requireCondition(expected[0] === 'unconfirmed' || tier !== 'dynamic-native-only', 'Native-only evidence cannot confirm a sandbox failure.');
  }
  function matchingKnowledgeBase(kb, report) {
    const target = report.target_runtime, version = normalizedVersion(target.version);
    return object(kb) && kb.snapshot_version === report.kb_snapshot_version && array(kb.runtime_releases?.[target.name]).includes(version) && array(kb.entries).some((entry) => object(entry) && entry.runtime === target.name && array(entry.runtime_versions).includes(version) && array(entry.architectures).includes(target.architecture));
  }
  // The comparison envelope is a collection of independently graded reports.
  // Derive its displayed observations again; an imported summary is not proof.
  function sameJSON(a, b) {
    if (a === b) return true;
    if (Array.isArray(a) && Array.isArray(b)) return a.length === b.length && a.every((value, index) => sameJSON(value, b[index]));
    if (object(a) && object(b)) {
      const keys = Object.keys(a).sort(), other = Object.keys(b).sort();
      return sameJSON(keys, other) && keys.every((key) => sameJSON(a[key], b[key]));
    }
    return false;
  }
  function matrixIntact(run) {
    const s = run.trace_summary;
    return run.infrastructure_error == null && Number.isSafeInteger(s.event_count) && s.event_count > 0 && s.truncated === false && s.unfinished_count === 0 && (s.discarded_guest_records ?? 0) === 0;
  }
  function matrixStable(runs, stream) {
    if (!runs.length || !validDigest(runs[0][stream])) return null;
    return runs.every((run) => run[stream] === runs[0][stream]) ? runs[0][stream] : null;
  }
  function matrixOutcome(report) {
    const d = report.dynamic;
    if (!d || d.sandbox.length !== (d.profile.repetitions ?? 3) || !d.sandbox.every(matrixIntact)) return 'unavailable';
    const passed = d.sandbox.filter((run) => run.exit_code === (d.profile.expected_exit_code ?? 0) && run.timed_out === false).length;
    return passed === d.sandbox.length ? 'success' : passed === 0 ? 'failure' : 'mixed';
  }
  function normalizeMatrix(input) {
    requireCondition(object(input) && input.schema_version === '1.1' && input.report_kind === 'runtime-comparison', 'Expected a schema 1.1 runtime-comparison envelope.');
    requireCondition(Array.isArray(input.reports) && input.reports.length === 2 && input.reports.every((report) => object(report) && report.schema_version === '1.0'), 'A runtime comparison requires two complete schema 1.0 report objects.');
    const reports = input.reports.map(normalizeReport), [a, b] = reports;
    requireCondition(a.target_runtime.name === 'gvisor' && b.target_runtime.name === 'kata', 'Comparison reports must be ordered gVisor then Kata.');
    requireCondition(reports.every((report) => !['', 'unversioned', 'unknown', 'latest'].includes(normalizedVersion(report.target_runtime.version))), 'Runtime comparison versions must be explicitly pinned.');
    requireCondition(validDigest(a.image_digest) && a.image_digest === b.image_digest && a.platform === b.platform, 'Comparison reports must identify the same image digest and architecture.');
    requireCondition(input.image_digest === a.image_digest && input.platform === a.platform && sameJSON(input.target_runtimes, reports.map((report) => report.target_runtime)), 'Comparison envelope identity contradicts its embedded reports.');
    requireCondition(input.authenticated === false && object(input.report_digests) && validDigest(input.report_digests.gvisor) && validDigest(input.report_digests.kata), 'Comparison digest metadata or authentication claim is invalid.');
    const limits = [], derived = { comparable: false, outcome_difference: null, stdout_difference: null, stderr_difference: null, outcomes: {}, locally_collected_pair: false };
    let profile = null;
    for (const report of reports) {
      const d = report.dynamic;
      if (d) {
        const repetitions = d.profile.repetitions ?? 3;
        requireCondition(Number.isSafeInteger(repetitions) && repetitions > 0 && repetitions <= 20 && Number.isInteger(d.profile.expected_exit_code ?? 0), 'Comparison workload counts or expected exit code are invalid.');
        requireCondition([d.profile.compare_stdout, d.profile.compare_stderr].every((flag) => flag === undefined || typeof flag === 'boolean'), 'Comparison output assertions must be booleans.');
        requireCondition([...d.native, ...d.sandbox].every((run) => (run.exit_code === null || Number.isInteger(run.exit_code)) && typeof run.timed_out === 'boolean' && typeof run.runtime_version === 'string' && validDigest(run.stdout_sha256) && validDigest(run.stderr_sha256)), 'Comparison observations require exit status, runtime version and output digests.');
      }
      derived.outcomes[report.target_runtime.name] = matrixOutcome(report);
    }
    if (a.dynamic && b.dynamic) {
      const ad = a.dynamic, bd = b.dynamic;
      requireCondition(ad.profile_sha256 === bd.profile_sha256 && sameJSON(ad.profile, bd.profile), 'Comparison workload profile identities or definitions differ.');
      profile = ad.profile_sha256;
      for (const report of reports) {
        const d = report.dynamic, name = report.target_runtime.name;
        if (d.native.length !== (d.profile.repetitions ?? 3) || !d.native.every((run) => matrixIntact(run) && run.exit_code === (d.profile.expected_exit_code ?? 0) && run.timed_out === false)) limits.push(`${name}: a complete successful native baseline is required.`);
        if (d.sandbox.length !== (d.profile.repetitions ?? 3) || !d.sandbox.every(matrixIntact)) limits.push(`${name}: sandbox observations are missing, incomplete, or contain infrastructure errors.`);
      }
      const versions = (runs) => [...new Set(runs.map((run) => run.runtime_version))].sort();
      if (!sameJSON(versions(ad.native), versions(bd.native))) limits.push('The two native baselines declare different runc versions.');
      for (const [stream, asserted] of [['stdout', ad.profile.compare_stdout], ['stderr', ad.profile.compare_stderr]]) {
        if (asserted && (matrixStable(ad.native, `${stream}_sha256`) === null || matrixStable(ad.native, `${stream}_sha256`) !== matrixStable(bd.native, `${stream}_sha256`))) limits.push(`Native baseline ${stream} is unstable or differs between the separate runs.`);
      }
      if (!limits.length) {
        const outcomes = (runs) => runs.map((run) => JSON.stringify([run.exit_code, run.timed_out])).sort();
        derived.outcome_difference = !sameJSON(outcomes(ad.sandbox), outcomes(bd.sandbox));
        for (const [stream, asserted] of [['stdout', ad.profile.compare_stdout], ['stderr', ad.profile.compare_stderr]]) {
          const oldHash = matrixStable(ad.sandbox, `${stream}_sha256`), newHash = matrixStable(bd.sandbox, `${stream}_sha256`);
          if (asserted && oldHash !== null && newHash !== null) derived[`${stream}_difference`] = oldHash !== newHash;
        }
      }
    } else limits.push('Both runtime reports need dynamic observations to compare outcomes; static capabilities remain unconfirmed.');
    derived.comparable = limits.length === 0;
    derived.locally_collected_pair = derived.comparable && reports.every((report) => report.dynamic?.provenance === 'locally-executed');
    requireCondition(input.profile_sha256 === profile && object(input.cross_runtime) && input.cross_runtime.baseline_relationship === 'separate-native-executions', 'Comparison profile or native-baseline relationship is inconsistent.');
    for (const [key, value] of Object.entries(derived)) requireCondition(sameJSON(input.cross_runtime[key], value), `Comparison ${key} contradicts its embedded observations.`);
    const incomplete = [...reports.flatMap((report) => report.incomplete_reasons.map((reason) => `${report.target_runtime.name}: ${reason}`)), ...limits];
    requireCondition(input.status === (incomplete.length ? 'incomplete' : 'complete') && sameJSON(input.incomplete_reasons, incomplete), 'Comparison status or incomplete reasons contradict its embedded reports.');
    checkAssessment(input.status, input.assessment, reports.flatMap((report) => report.findings));
    return { reports, derived, limits, status: input.status, assessment: input.assessment };
  }
  function normalizeReport(input) {
    requireCondition(object(input), 'Expected a JSON report object.');
    if (input.version === '2.1.0' && Array.isArray(input.runs)) return normalizeSarif(input);
    requireCondition(input.schema_version === '1.0', 'Unsupported report schema. Expected SENTRYCHECK schema_version 1.0 or SARIF 2.1.0.');
    requireCondition(typeof input.image === 'string' && object(input.target_runtime), 'Report image and target_runtime are required.');
    checkTarget(input.target_runtime);
    requireCondition(input.platform === `linux/${input.target_runtime.architecture}`, 'Report platform contradicts its target architecture.');
    if (input.image_digest !== null && input.image_digest !== undefined) requireCondition(validDigest(input.image_digest), 'Image digest is invalid.');
    requireCondition(['complete', 'incomplete'].includes(input.status) && typeof input.assessment === 'string', 'Report must declare status and assessment.');
    requireCondition(Array.isArray(input.findings) && Array.isArray(input.candidate_gaps) && object(input.capability_set), 'Report findings, candidate_gaps and capability_set are required.');
    requireCondition(input.findings.every((f) => object(f) && typeof f.id === 'string' && typeof f.gap_id === 'string' && typeof f.description === 'string'), 'Each finding needs an id, gap_id and description.');
    requireCondition(input.candidate_gaps.every(object), 'Each candidate gap must be an object.');
    requireCondition(Array.isArray(input.incomplete_reasons) && (input.status === 'complete') === (input.incomplete_reasons.length === 0), 'Scan status contradicts its incomplete reasons.');
    requireCondition(Array.isArray(input.capability_set_only), 'Report capability_set_only must be an array.');
    if (input.dynamic !== null && input.dynamic !== undefined) {
      requireCondition(object(input.dynamic) && object(input.dynamic.profile) && Array.isArray(input.dynamic.native) && Array.isArray(input.dynamic.sandbox), 'Dynamic evidence needs a profile, native observations and sandbox observations.');
      checkTier(input.dynamic.evidence_tier, input.target_runtime);
      requireCondition(['locally-executed', 'imported-user-supplied'].includes(input.dynamic.provenance) && validDigest(input.dynamic.profile_sha256), 'Dynamic evidence lacks a valid provenance or profile digest.');
      requireCondition((input.dynamic.sandbox.length === 0) === (input.dynamic.evidence_tier === 'dynamic-native-only'), 'Evidence tier contradicts the presence of sandbox observations.');
      for (const run of [...input.dynamic.native, ...input.dynamic.sandbox]) requireCondition(object(run) && object(run.trace_summary) && object(run.trace_summary.syscalls) && object(run.trace_summary.errors), 'Each observation needs a trace summary with syscall and error maps.');
      requireCondition(input.dynamic.native.every((run) => run.runtime === 'runc'), 'Native observations must identify runc.');
      requireCondition(input.dynamic.sandbox.every((run) => run.runtime === input.target_runtime.name && normalizedVersion(run.runtime_version) === normalizedVersion(input.target_runtime.version)), 'Sandbox observations contradict the pinned target runtime.');
    }
    const findingIds = new Set();
    for (const finding of input.findings) {
      requireCondition(finding.id.length > 0 && !findingIds.has(finding.id) && object(input.dynamic) && finding.evidence_tier === input.dynamic.evidence_tier, 'Finding identifiers or evidence tiers contradict the report.');
      findingIds.add(finding.id);
      checkClassification(finding.severity, finding.failure_class, finding.evidence_tier, input.target_runtime);
    }
    if (input.status === 'complete') {
      const dynamic = input.dynamic;
      requireCondition(object(dynamic) && dynamic.provenance === 'locally-executed' && dynamic.native.length > 0 && dynamic.sandbox.length > 0 && validDigest(input.image_digest), 'A complete report must declare a digest-bound local native/sandbox comparison.');
      const repetitions = dynamic.profile.repetitions ?? 3, expectedExit = dynamic.profile.expected_exit_code ?? 0;
      requireCondition(dynamic.profile.coverage === 'representative' && Number.isSafeInteger(repetitions) && repetitions > 0 && dynamic.native.length === repetitions && dynamic.sandbox.length === repetitions, 'Complete evidence requires representative coverage and the requested observations.');
      requireCondition(Number.isInteger(expectedExit) && dynamic.native.every((run) => run.exit_code === expectedExit && run.timed_out === false), 'Complete evidence requires a successful native profile baseline.');
      requireCondition([...dynamic.native, ...dynamic.sandbox].every((run) => {
        const summary = run.trace_summary;
        return run.infrastructure_error == null && summary.truncated === false && Number.isSafeInteger(summary.event_count) && summary.event_count > 0 && summary.unfinished_count === 0 && (summary.discarded_guest_records ?? 0) === 0;
      }), 'Complete evidence contradicts missing, truncated, discarded or unfinished guest records.');
    }
    checkAssessment(input.status, input.assessment, input.findings);
    return { ...input, reduced: false };
  }
  function checkAssessment(status, declared, findings) {
    const severities = findings.map((f) => f.severity);
    requireCondition(severities.every((s) => ['hard-failure', 'silent-degradation', 'performance-regression', 'compatibility-risk'].includes(s)), 'Unrecognized finding severity.');
    const expected = severities.some((s) => s === 'hard-failure' || s === 'silent-degradation') ? 'incompatibility-observed' : severities.includes('performance-regression') ? 'performance-regression-observed' : status === 'complete' ? 'no-incompatibility-observed-in-profile' : 'insufficient-evidence';
    requireCondition(expected === declared, 'Assessment contradicts reported findings or scan status.');
  }
  function normalizeSarif(input) {
    requireCondition(input.runs.length === 1 && object(input.runs[0]) && input.runs[0].tool?.driver?.name === 'SENTRYCHECK', 'Open a SARIF export containing exactly one SENTRYCHECK run.');
    state.sarifRun = Math.min(state.sarifRun, input.runs.length - 1);
    const run = input.runs[state.sarifRun];
    const p = object(run.properties) ? run.properties : {};
    const driver = run.tool?.driver || {};
    requireCondition(Array.isArray(driver.rules) && Array.isArray(run.results), 'SARIF rules and results must be arrays.');
    const rules = driver.rules;
    const results = run.results;
    requireCondition(p.schemaVersion === '1.0' && ['complete', 'incomplete'].includes(p.scanStatus) && object(p.targetRuntime), 'SARIF is missing its SENTRYCHECK scan metadata.');
    checkTarget(p.targetRuntime);
    requireCondition(typeof p.image === 'string' && p.image.length > 0 && typeof p.kbSnapshot === 'string' && p.kbSnapshot.length > 0, 'SARIF must identify its image and KB snapshot.');
    requireCondition(Array.isArray(run.invocations) && run.invocations.length === 1 && object(run.invocations[0]) && run.invocations[0].executionSuccessful === (p.scanStatus === 'complete'), 'SARIF invocation contradicts its declared scan status.');
    for (const digest of [p.imageDigest, p.profileSha256]) if (digest !== null && digest !== undefined) requireCondition(validDigest(digest), 'SARIF contains an invalid image or profile digest.');
    if (p.provenance !== null && p.provenance !== undefined) requireCondition(['locally-executed', 'imported-user-supplied'].includes(p.provenance), 'SARIF execution provenance is unrecognized.');
    if (p.evidenceTier !== undefined) checkTier(p.evidenceTier, p.targetRuntime, true);
    if (p.scanStatus === 'complete') {
      requireCondition(p.provenance === 'locally-executed' && validDigest(p.imageDigest) && validDigest(p.profileSha256), 'Complete SARIF requires declared local execution and image/profile digests.');
      requireCondition(p.evidenceTier === undefined || ['dynamic-runsc-diff', 'dynamic-kata-diff'].includes(p.evidenceTier), 'Complete SARIF cannot declare static or native-only evidence.');
    }
    const ruleIds = new Set();
    for (const rule of rules) {
      requireCondition(object(rule) && typeof rule.id === 'string' && rule.id.length > 0 && !ruleIds.has(rule.id), 'SARIF rule identifiers are invalid or duplicated.');
      ruleIds.add(rule.id);
    }
    requireCondition(results.every((result) => object(result) && object(result.message) && typeof result.message.text === 'string'), 'SARIF results must contain text messages.');
    let commonTier = null;
    for (const result of results) {
      requireCondition(typeof result.ruleId === 'string' && ruleIds.has(result.ruleId), 'SARIF result refers to an unknown rule.');
      if (result.ruleIndex !== undefined) requireCondition(Number.isSafeInteger(result.ruleIndex) && result.ruleIndex >= 0 && rules[result.ruleIndex]?.id === result.ruleId, 'SARIF rule index contradicts its rule ID.');
      requireCondition(object(result.properties), 'SARIF result lacks SENTRYCHECK evidence metadata.');
      requireCondition(typeof result.level === 'string', 'SARIF result must declare a classification level.');
      const props = result.properties;
      checkClassification(props.severity, props.failureClass, props.evidenceTier, p.targetRuntime, result.level);
      requireCondition((commonTier === null || commonTier === props.evidenceTier) && (p.evidenceTier === undefined || p.evidenceTier === props.evidenceTier), 'SARIF result evidence tiers contradict one another.');
      commonTier = props.evidenceTier;
    }
    checkAssessment(p.scanStatus, p.assessment, results.map((result) => ({ severity: result.properties?.severity })));
    return {
      schema_version: text(p.schemaVersion, 'SARIF 2.1.0'), image: text(p.image, 'Image not recorded in SARIF'), image_digest: p.imageDigest, scanned_at: p.scannedAt,
      sentrycheck_version: driver.version, kb_snapshot_version: p.kbSnapshot, target_runtime: object(p.targetRuntime) ? p.targetRuntime : {}, profile_sha256: p.profileSha256,
      status: text(p.scanStatus, 'unknown'), assessment: text(p.assessment, 'unknown'), platform: p.targetRuntime?.architecture,
      duration_ms: p.durationMs, limitations: array(p.limitations), incomplete_reasons: array(run.invocations).flatMap((i) => array(i.toolExecutionNotifications).map((n) => n.message?.text).filter(Boolean)),
      findings: results.map((result, index) => {
        const props = object(result.properties) ? result.properties : {};
        const rule = rules.find((r) => r.id === result.ruleId) || {};
        return { id: text(props.findingId, `sarif-${index + 1}`), gap_id: text(result.ruleId, 'unclassified'), category: text(props.category, 'unclassified'), description: result.message.text,
          severity: text(props.severity, result.level === 'error' ? 'SARIF error' : text(result.level, 'unknown')), failure_class: text(props.failureClass, 'Not recorded'),
          evidence_tier: text(props.evidenceTier, 'Not recorded'), source_binary: props.sourceBinary, static_evidence: props.staticEvidence, dynamic_evidence: props.dynamicEvidence,
          causality: text(props.causality, 'Not recorded in this SARIF result.'), kb_citation: props.kbCitation || rule.properties?.citation || { title: rule.shortDescription?.text || result.ruleId, url: rule.helpUri } };
      }),
      candidate_gaps: null, capability_set: null, capability_set_only: null, dynamic: null, reduced: true, sarifCount: input.runs.length,
      sarifTool: text(driver.name, 'Unknown tool'), sarifTier: p.evidenceTier, sarifProvenance: p.provenance,
      silent_fallback_check: { performed: p.nodeIsolationChecked === true, note: 'SARIF does not include node-probe evidence. This viewer does not authenticate isolation claims.' },
    };
  }
  function loadPayload(payload, { demo = false, source = 'Embedded report', uploaded = false } = {}) {
    requireCondition(object(payload) && object(payload.report), 'Embedded payload must contain a report object.');
    state.sarifRun = 0;
    const matrix = payload.report.schema_version === '1.1' || payload.report.report_kind === 'runtime-comparison' ? normalizeMatrix(payload.report) : null;
    const report = matrix ? matrix.reports[0] : normalizeReport(payload.report);
    const kbSource = object(payload.kb) && Array.isArray(payload.kb.entries) ? payload.kb : null;
    const kb = matchingKnowledgeBase(kbSource, report) ? kbSource : null;
    state.payload = uploaded ? { report: payload.report, kb, validation: { semantic_consistency: false, authenticated: false, kb_note: 'Local file: browser structural checks only. No signature or Rust consistency validation was performed.' } } : payload;
    state.report = report; state.kb = kb; state.availableKb = kbSource; state.matrix = matrix; state.selectedRuntime = report.target_runtime.name; state.demo = demo; state.source = source; state.error = null;
    state.findingPage = 0; state.kbPage = 0; state.tracePage = 0; state.selectedRun = 0; state.syscallPage = 0;
    render();
  }
  function selectRuntime(runtime) {
    const report = state.matrix?.reports.find((entry) => entry.target_runtime.name === runtime);
    if (!report) return;
    state.selectedRuntime = runtime; state.report = report;
    state.kb = matchingKnowledgeBase(state.availableKb, report) ? state.availableKb : null;
    state.findingPage = 0; state.findingQuery = ''; state.findingSeverity = ''; state.kbPage = 0; state.kbQuery = ''; state.kbStatus = ''; state.tracePage = 0; state.selectedRun = 0; state.syscallPage = 0;
    location.hash = `${(location.hash.split('?')[0] || '#overview').split('/')[0]}?runtime=${runtime}`;
    render();
    $('matrix-runtime')?.focus();
  }
  function observations() {
    if (!state.report?.dynamic) return [];
    return [...array(state.report.dynamic.native).map((run, index) => ({ run, group: 'Native', label: `N${String(index + 1).padStart(2, '0')}` })), ...array(state.report.dynamic.sandbox).map((run, index) => ({ run, group: 'Sandbox', label: `S${String(index + 1).padStart(2, '0')}` }))];
  }
  function assessment() {
    const r = state.report;
    if (r.assessment === 'incompatibility-observed') return { title: 'Incompatibility observed in this profile', color: 'red', symbol: '!', note: 'Read the finding evidence and causality before deciding how to deploy this workload.' };
    if (r.assessment === 'performance-regression-observed') return { title: 'Performance regression observed', color: 'amber', symbol: '!', note: 'Timing evidence is bounded by this profile and analysis environment.' };
    if (r.status !== 'complete' || r.assessment === 'insufficient-evidence') return { title: 'Insufficient evidence for a compatibility assessment', color: 'amber', symbol: '?', note: 'The declared scan status is incomplete or unknown. Missing findings do not establish compatibility.' };
    if (r.assessment === 'no-incompatibility-observed-in-profile') return { title: 'No incompatibility observed in this profile', color: 'teal', symbol: '✓', note: 'This is a bounded observation. Untested code paths and deployment environments remain outside its coverage.' };
    return { title: 'Assessment not recognized by this viewer', color: 'amber', symbol: '?', note: `Reported assessment: ${text(r.assessment)}. No clean result is inferred.` };
  }
  function header(index, section, title, subtitle) {
    return el('div', { class: 'page-heading' }, el('div', {}, el('div', { class: 'eyebrow' }, el('span', { class: 'index' }, index), '//', section), el('h1', {}, title), el('p', { class: 'page-subtitle' }, subtitle)), el('div', { class: 'heading-side' }, el('div', { class: 'mono' }, state.demo ? 'ILLUSTRATIVE / DEMO' : text(state.report.scanned_at, 'SCAN DATE NOT RECORDED')), badge(state.report.reduced ? 'SARIF · reduced data' : `schema ${state.report.schema_version}`, 'gray')));
  }
  function metric(label, value, caption, name, color, textual = false) { return el('div', { class: 'metric' }, el('div', { class: 'metric-label' }, label, icon(name)), el('div', { class: `metric-value${textual ? ' text-value' : ''}` }, value), el('div', { class: 'metric-caption' }, caption), el('div', { class: `metric-accent ${color}` })); }
  function findingRow(finding, index, candidate = false) {
    return link([el('span', { class: `severity-mark ${candidate ? 'amber' : tone(finding.severity)}` }), el('div', {}, el('div', { class: 'row-title' }, finding.gap_id === 'gap-observed-workload-failure' ? 'Workload execution diverged' : human(finding.gap_id)), el('p', { class: 'row-description' }, text(finding.description)), el('div', { class: 'row-meta' }, badge(candidate ? 'unconfirmed candidate' : text(finding.severity), candidate ? 'amber' : tone(finding.severity)), candidate ? el('span', { class: 'mono' }, text(finding.syscall, 'subsystem marker')) : tierBadge(finding.evidence_tier))), el('span', { class: 'row-arrow', 'aria-hidden': 'true' }, '↗')], `#findings/${candidate ? 'candidate-' : ''}${index}`, 'finding-row');
  }
  function citationContent(citation) {
    const c = object(citation) ? citation : {};
    return body(external(text(c.title, 'Citation not recorded'), c.url, 'citation-link'), definitions([['Source revision', text(c.source_revision, 'Not recorded in this report'), true], ['Retrieved', text(c.retrieved_at), true]]), el('p', { class: 'source-label', style: 'margin-top:14px' }, text(c.url)), el('div', { class: 'trust-note' }, icon('info'), 'A source link is evidence context. This viewer does not authenticate the report or fetch the source.'));
  }
  function captureBar(summary) {
    const items = [['events', number(summary.event_count)], ['diagnostics', number(summary.diagnostic_lines)], ['discarded', number(summary.discarded_guest_records)], ['unfinished', number(summary.unfinished_count)]];
    const total = items.reduce((sum, item) => sum + (item[1] || 0), 0);
    return el('div', { class: 'capture-bar', 'aria-label': items.map(([name, n]) => `${n === null ? 'unavailable' : n} ${name}`).join(', ') }, items.filter((item) => item[1] > 0).map(([name, n]) => el('span', { class: name, style: `width:${n / total * 100}%` })));
  }
  function observationCard(item, index, selected = false, onselect = null) {
    const r = item.run; const summary = r.trace_summary || {};
    const attrs = { class: `observation${selected ? ' active' : ''}`, 'aria-label': `${item.group} observation ${item.label}, exit ${r.exit_code ?? 'unavailable'}, ${fmtMs(r.duration_ms)}` };
    if (onselect) { attrs.type = 'button'; attrs.onclick = onselect; attrs['aria-pressed'] = selected; } else attrs.href = `#traces/${index}`;
    return el(onselect ? 'button' : 'a', attrs, el('div', { class: 'observation-top' }, item.label, badge(r.timed_out ? 'timeout' : r.exit_code === null || r.exit_code === undefined ? 'exit ?' : `exit ${r.exit_code}`, r.timed_out || r.exit_code !== (state.report.dynamic?.profile?.expected_exit_code ?? 0) ? 'red' : 'gray')), el('div', { class: 'observation-time' }, number(r.duration_ms) === null ? '—' : r.duration_ms >= 1000 ? (r.duration_ms / 1000).toFixed(2) : r.duration_ms, el('small', {}, r.duration_ms >= 1000 ? 'sec' : 'ms')), el('div', { class: 'observation-label' }, `${item.group} · ${count(summary.event_count)} events`), captureBar(summary));
  }
  function captureLegend() { return el('div', { class: 'legend' }, el('span', {}, el('i'), 'Parsed events'), el('span', {}, el('i', { class: 'amber' }), 'Diagnostic lines'), el('span', {}, el('i', { class: 'red' }), 'Discarded guest records'), el('span', {}, 'Bars include unfinished calls where recorded.')); }
  function matrixSummary() {
    const matrix = state.matrix;
    if (!matrix) return null;
    const difference = (value) => value === null ? 'Unavailable / not asserted' : value ? 'Different recorded observations' : 'Same recorded observations';
    const table = el('div', { class: 'table-wrap' }, el('table', { class: 'data-table', 'aria-label': 'Runtime comparison observations' },
      el('thead', {}, el('tr', {}, ['Runtime / release', 'Observed outcome', 'Evidence tier', 'Provenance'].map((label) => el('th', { scope: 'col' }, label)))),
      el('tbody', {}, matrix.reports.map((report) => el('tr', {},
        el('th', { scope: 'row' }, report.target_runtime.name === 'gvisor' ? 'gVisor' : 'Kata', el('div', { class: 'mono' }, report.target_runtime.version)),
        el('td', {}, badge(human(matrix.derived.outcomes[report.target_runtime.name]), matrix.derived.outcomes[report.target_runtime.name] === 'failure' ? 'red' : 'amber')),
        el('td', {}, tierBadge(report.dynamic?.evidence_tier || 'static-only')),
        el('td', {}, text(report.dynamic?.provenance, 'No dynamic execution')))))));
    return el('section', { class: 'wide-section', id: 'matrix-summary' }, panel('Runtime comparison', [
      body(el('p', { class: 'detail-paragraph' }, 'Two separate native baselines; each runtime retains its own evidence grade. These observations cover the recorded profile and do not establish a runtime recommendation.'),
        definitions([['Comparison scope', matrix.derived.comparable ? 'Comparable recorded outcomes' : 'Insufficient comparison evidence'], ['Exit / timeout distribution', difference(matrix.derived.outcome_difference)], ['Declared stdout assertion', difference(matrix.derived.stdout_difference)], ['Declared stderr assertion', difference(matrix.derived.stderr_difference)]])),
      table,
      matrix.limits.length ? body(bulletList(matrix.limits)) : null,
      body(el('div', { class: 'trust-note' }, icon('info'), 'Browser calculations use recorded outcomes. Capture integrity, source-file digests, signatures and host equivalence are not verified here. Timing includes startup and tracing overhead.')),
    ], badge(`schema 1.1 · ${matrix.status}`, 'amber')));
  }
  function renderOverview() {
    const r = state.report, a = assessment(), runs = observations(), candidates = array(r.candidate_gaps);
    const main = $('main-content');
    main.append(header('01', 'Report overview', 'Workload compatibility', text(r.image)), el('div', { class: `status-strip ${a.color === 'red' ? '' : `status-${a.color}`}` }, el('span', { class: 'status-symbol', 'aria-hidden': 'true' }, a.symbol), el('div', { class: 'status-content' }, el('h3', {}, a.title), el('p', {}, a.note)), link('Inspect evidence →', '#findings', 'button button-quiet')),
      el('div', { class: 'metrics' }, metric('Reported findings', count(r.findings.length), `${r.findings.filter((f) => f.severity === 'hard-failure').length} hard-failure findings`, 'flag', a.color), metric('Target runtime', r.target_runtime.name === 'gvisor' ? 'gVisor' : human(r.target_runtime.name), text(r.target_runtime.version), 'cube', 'teal', true), metric('Run observations', r.reduced ? 'Unavailable' : count(runs.length), r.reduced ? 'Not carried in SARIF' : `${array(r.dynamic?.native).length} native · ${array(r.dynamic?.sandbox).length} sandbox`, 'trace', 'teal', r.reduced), metric('Profile coverage', r.reduced ? 'Unavailable' : human(r.dynamic?.profile?.coverage || 'not recorded'), r.reduced ? 'Full JSON has profile details' : text(r.dynamic?.profile?.name, 'No dynamic profile recorded'), 'clock', 'amber', true)));
    if (state.matrix) main.append(matrixSummary());
    const findingsPanel = panel('Reported findings', r.findings.length ? el('div', {}, r.findings.slice(0, 4).map((f, i) => findingRow(f, i))) : empty('No findings in this report', 'Use the declared assessment and scan status. An empty finding list is not a compatibility guarantee.'), link('View all →', '#findings', 'button button-quiet'), r.reduced ? 'SARIF preserves findings; full candidate and trace data are unavailable.' : `${count(candidates.length)} static candidates are listed separately and remain unconfirmed.`);
    const evidencePanel = panel('Evidence record', body(definitions([['Scan status', badge(text(r.status), r.status === 'complete' ? 'gray' : 'amber')], ['Evidence tier', tierBadge(r.dynamic?.evidence_tier || r.sarifTier || (r.reduced ? 'not recorded' : 'static-only'))], ['Provenance', text(r.dynamic?.provenance || r.sarifProvenance), true], ['KB snapshot', text(r.kb_snapshot_version), true], ['Architecture', text(r.target_runtime.architecture), true], ['Scan duration', fmtMs(r.duration_ms), true]]), el('div', { class: 'trust-note' }, icon('shield'), state.demo ? 'Illustrative sample. No workload ran for this view.' : state.payload.validation?.semantic_consistency === true ? 'CLI consistency checks were reported. Report authenticity is not verified by this viewer.' : 'Browser structural checks only. Semantic consistency and authenticity are not verified.')));
    main.append(el('div', { class: 'main-grid' }, findingsPanel, el('div', { class: 'stack' }, evidencePanel)));
    if (runs.length) main.append(el('section', { class: 'wide-section' }, el('div', { class: 'section-heading' }, el('div', {}, el('h2', {}, 'Execution observations'), el('p', {}, 'Native observations, then sandbox observations. Array order; no wall-clock timeline.')), link('Explore traces →', '#traces', 'button button-quiet')), el('div', { class: 'observations' }, runs.slice(0, 6).map((item, i) => observationCard(item, i))), captureLegend()));
    if (r.reduced) main.append(el('div', { class: 'unavailable wide-section' }, 'SARIF is a reduced interchange format. Open the original JSON for static capabilities, profile settings and run trace summaries.'));
    const reasons = array(r.incomplete_reasons);
    if (reasons.length) main.append(el('div', { class: 'wide-section' }, panel('Incomplete scan reasons', body(bulletList(reasons)))));
    main.append(el('div', { class: 'scope-strip' }, icon('shield'), el('p', {}, el('strong', {}, 'Isolation boundary: '), r.silent_fallback_check?.performed ? 'A cluster check is declared in the input; this viewer does not authenticate it. ' : 'No node isolation check is established by this report view. ', text(r.silent_fallback_check?.note, 'Use node-probe evidence to assess the deployed runtime.'))));
    main.append(el('section', { class: 'wide-section' }, panel('Report identity & scope', body(definitions([['Image digest', text(r.image_digest), true], ['Profile SHA-256', text(r.dynamic?.profile_sha256 || r.profile_sha256), true], ['Input SHA-256', text(state.payload.input_sha256, 'Not computed by this viewer'), true], ['Source', state.source], ['Rendered at', text(state.payload.rendered_at, 'Not recorded'), true], ['Rendered by', state.demo ? 'Illustrative demo' : text(state.payload.generator_version, 'Browser local-file viewer')]]), array(r.limitations).length ? el('div', { class: 'trust-note' }, icon('info'), el('div', {}, bulletList(r.limitations))) : null))));
  }
  function filterBar(query, onquery, options, selected, onselect, placeholder) {
    const input = el('input', { type: 'search', value: query, placeholder, 'aria-label': placeholder, oninput: (event) => onquery(event.target.value) });
    const select = el('select', { 'aria-label': 'Filter status or severity', onchange: (event) => onselect(event.target.value) }, options.map(([value, label]) => el('option', { value, ...(value === selected ? { selected: 'selected' } : {}) }, label)));
    return el('div', { class: 'filter-bar' }, el('label', { class: 'search-field' }, icon('search'), input), select);
  }
  function pager(total, page, size, change) {
    const pages = Math.max(1, Math.ceil(total / size));
    return el('div', { class: 'pagination' }, el('span', {}, total ? `${count(page * size + 1)}–${count(Math.min(total, (page + 1) * size))} of ${count(total)}` : '0 results', ` · ${size} per page`), el('div', { class: 'pagination-actions' }, el('button', { class: 'button', disabled: page <= 0, onclick: () => change(page - 1) }, '← Previous'), el('button', { class: 'button', disabled: page >= pages - 1, onclick: () => change(page + 1) }, 'Next →')));
  }
  function tab(label, n, active, onclick) { return el('button', { type: 'button', class: `tab${active ? ' active' : ''}`, 'aria-pressed': active, onclick }, label, n === null ? null : el('span', {}, count(n))); }
  function renderFindings() {
    const main = $('main-content'), r = state.report;
    main.append(header('02', 'Evidence inspection', 'Findings & candidates', 'Findings carry observed or documented evidence. Static candidates indicate possible capabilities; they are not confirmed failures.'));
    main.append(el('div', { class: 'tabs' }, tab('Reported findings', r.findings.length, state.findingTab === 'findings', () => { state.findingTab = 'findings'; state.findingPage = 0; render(); }), tab('Static candidates', r.reduced ? null : array(r.candidate_gaps).length, state.findingTab === 'candidates', () => { state.findingTab = 'candidates'; state.findingPage = 0; render(); })));
    if (state.findingTab === 'candidates' && r.reduced) { main.append(el('div', { class: 'unavailable' }, 'Candidate details are not included in SARIF. Open the original JSON report to inspect them.')); return; }
    const candidate = state.findingTab === 'candidates';
    const data = candidate ? array(r.candidate_gaps) : r.findings;
    const options = [['', candidate ? 'All version matches' : 'All severities'], ...(candidate ? [['matched', 'Target version matched'], ['unmatched', 'Target version unmatched']] : [...new Set(data.map((f) => text(f.severity)))].sort().map((s) => [s, human(s)]))];
    if (!options.some(([value]) => value === state.findingSeverity)) state.findingSeverity = '';
    const zone = el('div');
    const update = () => {
      const query = state.findingQuery.toLowerCase();
      const filtered = data.map((finding, index) => ({ finding, index })).filter(({ finding: f }) => [f.id, f.gap_id, f.category, f.description, f.source_binary, f.syscall].filter((v) => typeof v === 'string').some((v) => v.toLowerCase().includes(query)) && (!state.findingSeverity || (candidate ? (f.version_match === true ? 'matched' : 'unmatched') === state.findingSeverity : f.severity === state.findingSeverity)));
      state.findingPage = Math.min(state.findingPage, Math.max(0, Math.ceil(filtered.length / PAGE) - 1));
      zone.replaceChildren(el('div', { class: 'list-count' }, candidate ? 'UNCONFIRMED CAPABILITY CANDIDATES' : 'REPORTED EVIDENCE', ` / ${count(filtered.length)} records`), el('div', { class: 'panel' }, filtered.length ? filtered.slice(state.findingPage * PAGE, (state.findingPage + 1) * PAGE).map(({ finding, index }) => findingRow(finding, index, candidate)) : empty('No matching records', 'Try another search or filter. No compatibility conclusion is inferred from this empty view.')), pager(filtered.length, state.findingPage, PAGE, (page) => { state.findingPage = page; update(); }));
    };
    main.append(filterBar(state.findingQuery, (q) => { state.findingQuery = q; state.findingPage = 0; update(); }, options, state.findingSeverity, (v) => { state.findingSeverity = v; state.findingPage = 0; update(); }, 'Search gap, syscall, binary or description…'), zone);
    update();
    if (candidate) main.append(el('div', { class: 'scope-strip' }, icon('info'), el('p', {}, 'Static extraction is an incomplete capability approximation. Runtime probing, fallback and input coverage determine which paths execute.')));
  }
  function boundedJSON(value) {
    if (value === null || value === undefined) return 'Not recorded';
    let budget = 200;
    const seen = new WeakSet();
    return JSON.stringify(value, (_key, item) => {
      if (--budget < 0) return '[Additional evidence omitted from preview]';
      if (typeof item === 'string' && item.length > 2000) return `${item.slice(0, 2000)}… [truncated preview]`;
      if (object(item) || Array.isArray(item)) { if (seen.has(item)) return '[Repeated object]'; seen.add(item); if (Array.isArray(item) && item.length > 40) return [...item.slice(0, 40), '[Additional items omitted from preview]']; }
      return item;
    }, 2).slice(0, 24000);
  }
  function renderDetail(key) {
    const candidate = key.startsWith('candidate-'), raw = candidate ? key.slice(10) : key;
    if (!/^\d+$/.test(raw)) { $('main-content').append(empty('Finding not found', 'Select a finding from the report list.')); return; }
    const f = (candidate ? array(state.report.candidate_gaps) : state.report.findings)[Number(raw)];
    if (!f) { $('main-content').append(empty('Finding not found', 'This record does not exist in the loaded report.')); return; }
    const staticEvidence = object(f.static_evidence) ? f.static_evidence : {};
    const c = candidate ? f.citation : f.kb_citation;
    const main = $('main-content');
    main.append(link('← Back to findings', '#findings', 'back-link'), el('div', { class: 'eyebrow' }, candidate ? 'UNCONFIRMED CANDIDATE' : text(f.id), '//', text(f.category)), el('h1', { class: 'detail-title' }, human(f.gap_id)), el('div', { class: 'row-meta' }, badge(candidate ? 'static candidate' : text(f.severity), candidate ? 'amber' : tone(f.severity)), candidate ? badge(f.version_match ? 'version matched' : 'version not matched', 'gray') : tierBadge(f.evidence_tier), candidate ? null : badge(text(f.failure_class), 'gray')), el('p', { class: 'detail-description' }, text(f.description)));
    const evidence = candidate ? panel('Candidate context', body(definitions([['Source binary', text(f.source_binary), true], ['Syscall', text(f.syscall), true], ['Target version', f.version_match ? 'Matches the cited record' : 'Does not match the cited record']]), el('div', { class: 'trust-note' }, icon('info'), 'Presence is not execution. This candidate does not establish workload incompatibility.'))) : panel('Observed evidence', body(el('h3', {}, 'Causality'), el('p', { class: 'detail-paragraph', style: 'margin:8px 0 20px' }, text(f.causality, 'Not recorded; do not infer that this syscall caused a failure.')), el('h3', {}, 'Dynamic evidence'), el('pre', { class: 'code-block', style: 'margin-top:10px' }, boundedJSON(f.dynamic_evidence)), el('div', { class: 'trust-note' }, icon('info'), 'Evidence preview is bounded. The original JSON preserves the full observation.')));
    const source = panel('Source & static context', body(definitions([['Source binary', text(f.source_binary || staticEvidence.source_binary), true], ['Syscall', text(staticEvidence.syscall, candidate ? text(f.syscall) : 'Not recorded'), true], ['Offset', text(staticEvidence.source_offset), true], ['Resolution', text(staticEvidence.resolution_confidence), true]]), hashRow('Source binary SHA-256', staticEvidence.source_digest)));
    main.append(el('div', { class: 'detail-grid' }, el('div', { class: 'stack' }, evidence, source), el('div', { class: 'stack' }, panel('Cited source', citationContent(c)), panel('Report context', body(definitions([['Target runtime', `${text(state.report.target_runtime.name)} ${text(state.report.target_runtime.version)}`, true], ['KB snapshot', text(state.report.kb_snapshot_version), true], ['Scan status', text(state.report.status), true]]))))));
    const kbEntry = array(state.kb?.entries).find((entry) => entry.id === f.gap_id);
    if (kbEntry) main.append(el('div', { class: 'wide-section' }, panel('Matching KB record · separate source context', body(el('p', { class: 'detail-paragraph' }, text(kbEntry.description)), hashRow('KB source revision', kbEntry.citation?.source_revision), el('p', { class: 'file-note' }, 'This KB record does not supply any citation fields missing from the original finding.')), link('Browse KB →', '#knowledge', 'button button-quiet'))));
  }
  function kbRow(entry) {
    return el('article', { class: 'kb-row' }, el('div', { class: 'kb-row-top' }, el('h3', {}, text(entry.id)), badge(text(entry.status), tone(entry.status))), el('p', {}, text(entry.description)), el('div', { class: 'row-meta' }, badge(text(entry.category), 'gray'), el('span', { class: 'mono' }, `${text(entry.runtime)} / ${array(entry.architectures).join(', ') || 'architecture not recorded'}`), el('span', { class: 'mono' }, array(entry.runtime_versions).join(', '))), el('div', { class: 'kb-revision' }, 'Source revision: ', text(entry.citation?.source_revision)), external(text(entry.citation?.title, 'Source citation'), entry.citation?.url, 'kb-source'));
  }
  function renderKnowledge() {
    const main = $('main-content'), kb = state.kb;
    main.append(header('03', 'Versioned knowledge', 'Compatibility knowledge base', 'Source-backed gap records and syscall support, scoped to a specific runtime release and architecture.'));
    if (!kb) { main.append(el('div', { class: 'panel' }, empty('No matching knowledge base attached', state.matrix ? `No attached snapshot covers ${state.report.target_runtime.name} ${state.report.target_runtime.version}. This runtime's finding citations remain available; another runtime's KB is not reused.` : text(state.payload.validation?.kb_note, 'Finding citations remain available. Generate this HTML with a matching KB snapshot to browse its entries.')))); return; }
    main.append(panel('Snapshot identity', body(definitions([['Snapshot', text(kb.snapshot_version), true], ['Source commit', text(kb.source_commit), true], ['Created', text(kb.created_at), true], ['Release scope', Object.entries(object(kb.runtime_releases) ? kb.runtime_releases : {}).map(([runtime, versions]) => `${runtime}: ${array(versions).join(', ') || 'none'}`).join(' · '), true]]), el('details', { style: 'margin-top:16px' }, el('summary', { class: 'file-note' }, 'Source hashes'), Object.entries(object(kb.source_hashes) ? kb.source_hashes : {}).map(([path, digest]) => hashRow(path, digest))))));
    main.append(el('div', { class: 'tabs wide-section' }, tab('Gap records', array(kb.entries).length, state.kbTab === 'gaps', () => { state.kbTab = 'gaps'; state.kbPage = 0; state.kbStatus = ''; render(); }), tab('Syscall support', array(kb.syscall_support).length, state.kbTab === 'syscalls', () => { state.kbTab = 'syscalls'; state.kbPage = 0; state.kbStatus = ''; render(); })));
    const entries = state.kbTab === 'gaps' ? kb.entries : array(kb.syscall_support), zone = el('div');
    const options = [['', 'All statuses'], ...[...new Set(entries.map((entry) => text(entry.status)))].sort().map((status) => [status, human(status)])];
    const update = () => {
      const q = state.kbQuery.toLowerCase();
      const filtered = entries.filter((entry) => [entry.id, entry.syscall, entry.description, entry.detail, entry.category, entry.architecture, ...array(entry.architectures)].filter((v) => typeof v === 'string').some((v) => v.toLowerCase().includes(q)) && (!state.kbStatus || entry.status === state.kbStatus));
      state.kbPage = Math.min(state.kbPage, Math.max(0, Math.ceil(filtered.length / PAGE) - 1));
      const slice = filtered.slice(state.kbPage * PAGE, (state.kbPage + 1) * PAGE);
      const content = !slice.length ? empty('No matching records', 'Try another term or status.') : state.kbTab === 'gaps' ? slice.map(kbRow) : el('div', { class: 'table-wrap' }, el('table', { class: 'data-table' }, el('thead', {}, el('tr', {}, ['Syscall', 'Arch / number', 'Support', 'Source detail'].map((label) => el('th', { scope: 'col' }, label)))), el('tbody', {}, slice.map((entry) => el('tr', {}, el('td', { class: 'mono' }, text(entry.syscall)), el('td', { class: 'mono' }, `${text(entry.architecture)} / ${number(entry.number) ?? '—'}`), el('td', {}, badge(text(entry.status), tone(entry.status))), el('td', {}, text(entry.detail, 'No extra detail'), el('div', { class: 'source-label' }, `Source line ${number(entry.source_line) ?? 'not recorded'}`)))))));
      zone.replaceChildren(el('p', { class: 'list-count' }, `${count(filtered.length)} matching records`), el('div', { class: 'panel' }, content), pager(filtered.length, state.kbPage, PAGE, (page) => { state.kbPage = page; update(); }));
    };
    main.append(filterBar(state.kbQuery, (q) => { state.kbQuery = q; state.kbPage = 0; update(); }, options, state.kbStatus, (v) => { state.kbStatus = v; state.kbPage = 0; update(); }, 'Search syscall, category, architecture or description…'), zone);
    update();
    main.append(el('div', { class: 'scope-strip' }, icon('book'), el('p', {}, 'A syscall support table does not predict workload behavior on its own. Probe and fallback paths require dynamic evidence.')));
  }
  function renderTraces(key) {
    const main = $('main-content'), r = state.report, all = observations();
    main.append(header('04', 'Trace timeline', 'Execution evidence', 'Ordered, per-run observations. Native and sandbox arrays are grouped; no timestamps or cross-run chronology are invented.'));
    if (r.reduced || !all.length) { main.append(el('div', { class: 'panel' }, empty(r.reduced ? 'Trace summaries unavailable in SARIF' : 'No dynamic observations recorded', r.reduced ? 'Open the full JSON report to inspect run counts, capture diagnostics and syscall summaries.' : 'Static extraction cannot confirm which paths execute. This view does not imply zero syscall use.'))); return; }
    if (key && /^\d+$/.test(key) && Number(key) < all.length) { state.selectedRun = Number(key); state.tracePage = Math.floor(state.selectedRun / 6); }
    state.selectedRun = Math.min(state.selectedRun, all.length - 1);
    const sequence = el('div'), detail = el('div');
    const showDetail = () => {
      const { run, group, label } = all[state.selectedRun], s = run.trace_summary, syscalls = Object.entries(s.syscalls).filter(([, n]) => number(n) !== null).sort((a, b) => b[1] - a[1]);
      const errors = Object.entries(s.errors).filter(([, n]) => number(n) !== null).sort((a, b) => b[1] - a[1]);
      detail.replaceChildren();
      const counters = [['Parsed events', s.event_count, ''], ['Diagnostic lines', s.diagnostic_lines, 'warn'], ['Discarded records', s.discarded_guest_records, 'error'], ['Unfinished calls', s.unfinished_count, 'warn']];
      detail.append(el('div', { class: 'section-heading wide-section' }, el('div', {}, el('h2', {}, `${label} / ${group} observation`), el('p', {}, `${text(run.runtime)} ${text(run.runtime_version)} · ${text(run.trace_kind)}`)), badge(run.infrastructure_error || s.truncated || (s.discarded_guest_records || 0) > 0 || (s.unfinished_count || 0) > 0 ? 'inspect capture integrity' : 'see declared scan status', run.infrastructure_error || s.truncated ? 'red' : 'gray')), el('div', { class: 'trace-counters' }, counters.map(([title, value, color]) => el('div', { class: `trace-counter ${color}` }, el('strong', {}, count(value)), el('span', {}, title)))));
      if (run.infrastructure_error) detail.append(el('div', { class: 'error-banner' }, 'Infrastructure error: ', text(run.infrastructure_error)));
      const syscallZone = el('div');
      const syscallTable = () => {
        state.syscallPage = Math.min(state.syscallPage, Math.max(0, Math.ceil(syscalls.length / PAGE) - 1));
        syscallZone.replaceChildren(el('div', { class: 'table-wrap' }, el('table', { class: 'data-table' }, el('thead', {}, el('tr', {}, el('th', { scope: 'col' }, 'Syscall'), el('th', { scope: 'col', class: 'numeric' }, 'Count'), el('th', { scope: 'col', class: 'numeric' }, 'Share of parsed'))), el('tbody', {}, syscalls.slice(state.syscallPage * PAGE, (state.syscallPage + 1) * PAGE).map(([name, n]) => el('tr', {}, el('td', { class: 'mono' }, name), el('td', { class: 'numeric' }, count(n)), el('td', { class: 'numeric' }, number(s.event_count) && s.event_count > 0 ? `${(n / s.event_count * 100).toFixed(1)}%` : '—')))))), el('div', { style: 'padding:0 16px 16px' }, pager(syscalls.length, state.syscallPage, PAGE, (page) => { state.syscallPage = page; syscallTable(); })));
      };
      syscallTable();
      const summary = panel('Observation metadata', body(definitions([['Duration', fmtMs(run.duration_ms), true], ['Exit code', run.exit_code === null || run.exit_code === undefined ? 'Not recorded' : String(run.exit_code), true], ['Timed out', run.timed_out === true ? 'Yes' : run.timed_out === false ? 'No' : 'Not recorded'], ['Trace truncated', s.truncated === true ? 'Yes' : s.truncated === false ? 'No' : 'Not recorded'], ['Legacy unparsed', count(s.unparsed_lines), true], ['Trace artifact', text(run.trace_ref), true]]), el('div', { class: 'trust-note' }, icon('info'), 'Diagnostics are runner log lines. Discarded guest records are lost or malformed trace evidence. They must not be treated as interchangeable.')));
      detail.append(el('div', { class: 'trace-layout' }, panel(`Syscall summary / ${count(syscalls.length)} types`, syscallZone, null, 'Counts come from the report summary. Raw events are not rendered; local file imports receive structural checks only.'), el('div', { class: 'stack' }, summary, panel('Observed syscall errors', errors.length ? el('div', { class: 'table-wrap' }, el('table', { class: 'data-table' }, el('thead', {}, el('tr', {}, el('th', { scope: 'col' }, 'Syscall / errno'), el('th', { scope: 'col', class: 'numeric' }, 'Count'))), el('tbody', {}, errors.slice(0, PAGE).map(([name, n]) => el('tr', {}, el('td', { class: 'mono' }, name), el('td', { class: 'numeric' }, count(n))))))) : body(el('p', { class: 'detail-paragraph' }, 'No error entries are recorded in this summary.')), null, errors.length > PAGE ? `Showing the ${PAGE} most frequent error types of ${errors.length}.` : 'An errno can be an intentional capability probe. It is not automatically a workload failure.'))));
      detail.append(el('div', { class: 'wide-section' }, panel('Artifact fingerprints', body(hashRow('Trace SHA-256', run.trace_sha256), hashRow('Stdout SHA-256', run.stdout_sha256), hashRow('Stderr SHA-256', run.stderr_sha256)), null, 'Hashes identify artifacts recorded by the scanner. This viewer does not read or authenticate the external artifact files.')));
    };
    const showSequence = () => {
      sequence.replaceChildren(el('div', { class: 'observations' }, all.slice(state.tracePage * 6, (state.tracePage + 1) * 6).map((item, i) => observationCard(item, state.tracePage * 6 + i, state.selectedRun === state.tracePage * 6 + i, () => { state.selectedRun = state.tracePage * 6 + i; state.syscallPage = 0; history.replaceState(null, '', `#traces/${state.selectedRun}`); showSequence(); showDetail(); }))), captureLegend());
      if (all.length > 6) sequence.append(pager(all.length, state.tracePage, 6, (page) => { state.tracePage = page; showSequence(); }));
    };
    main.append(panel('Workload profile', body(definitions([['Name', text(r.dynamic.profile?.name), true], ['Coverage', text(r.dynamic.profile?.coverage), true], ['Repetitions', count(r.dynamic.profile?.repetitions), true], ['Timeout', `${count(r.dynamic.profile?.timeout_seconds)} seconds`, true], ['Command', array(r.dynamic.profile?.command).map((part) => JSON.stringify(part)).join(' ') || 'Image entrypoint / command', true]]), el('p', { class: 'detail-paragraph', style: 'margin-top:14px' }, text(r.dynamic.profile?.description, 'No description recorded.')))), el('section', { class: 'wide-section' }, sequence), detail);
    showSequence(); showDetail();
    const notes = [...array(r.dynamic.fallback_observations), ...array(r.dynamic.warnings)];
    if (notes.length) main.append(el('div', { class: 'wide-section' }, panel('Fallback observations & capture notes', body(bulletList(notes)))));
  }
  function notices() {
    const node = $('global-notice'); node.replaceChildren();
    if (state.demo) node.append(el('div', { class: 'demo-banner' }, el('strong', {}, 'ILLUSTRATIVE DEMO'), 'Sample observations, not a workload scan. Open a local report to inspect your own evidence.'));
    if (state.error) node.append(el('div', { class: 'error-banner' }, el('strong', {}, 'Could not open report.'), state.error, state.report ? 'The previous report remains displayed.' : ''));
    if (state.matrix) node.append(el('div', { class: 'information-banner', id: 'matrix-runtime-switcher' }, icon('cube'),
      el('label', { for: 'matrix-runtime' }, 'Runtime evidence'),
      el('select', { id: 'matrix-runtime', 'aria-label': 'Runtime evidence', onchange: (event) => selectRuntime(event.target.value) }, state.matrix.reports.map((report) => el('option', { value: report.target_runtime.name, ...(state.selectedRuntime === report.target_runtime.name ? { selected: 'selected' } : {}) }, `${report.target_runtime.name === 'gvisor' ? 'gVisor' : 'Kata'} ${report.target_runtime.version}`))),
      el('span', {}, 'Separate native executions · individual evidence grades')));
    if (state.report?.reduced) node.append(el('div', { class: 'information-banner' }, icon('info'), `SARIF ${state.report.sarifTool} run ${state.sarifRun + 1}/${state.report.sarifCount}. Reduced data; trace and candidate details require full JSON.`, state.report.sarifCount > 1 ? el('select', { 'aria-label': 'SARIF tool run', onchange: (event) => { state.sarifRun = Number(event.target.value); state.report = normalizeReport(state.payload.report); render(); } }, state.payload.report.runs.map((run, i) => el('option', { value: i, ...(i === state.sarifRun ? { selected: 'selected' } : {}) }, `Run ${i + 1}: ${text(run.tool?.driver?.name, 'Unknown tool')}`))) : null));
  }
  function render() {
    const rawHash = location.hash.slice(1), [routeHash, query = ''] = rawHash.split('?');
    const requestedRuntime = new URLSearchParams(query).get('runtime');
    if (state.matrix && ['gvisor', 'kata'].includes(requestedRuntime) && requestedRuntime !== state.selectedRuntime) {
      state.selectedRuntime = requestedRuntime;
      state.report = state.matrix.reports.find((report) => report.target_runtime.name === requestedRuntime);
      state.kb = matchingKnowledgeBase(state.availableKb, state.report) ? state.availableKb : null;
      state.findingPage = 0; state.kbPage = 0; state.tracePage = 0; state.selectedRun = 0; state.syscallPage = 0;
    }
    notices();
    if (!state.report) return;
    const hash = routeHash || 'overview', parts = hash.split('/'); parts[0] = ({ kb: 'knowledge', timeline: 'traces' })[parts[0]] || parts[0]; const route = ['overview', 'findings', 'knowledge', 'traces'].includes(parts[0]) ? parts[0] : 'overview';
    const routes = [['overview', 'Overview', 'grid'], ['findings', 'Findings', 'flag'], ['knowledge', 'Knowledge base', 'book'], ['traces', 'Trace timeline', 'trace']];
    $('navigation').replaceChildren(...routes.map(([path, label, name]) => el('a', { href: `#${path}`, class: `nav-item${route === path ? ' active' : ''}`, ...(route === path ? { 'aria-current': 'page' } : {}) }, icon(name), label, path === 'findings' ? el('span', { class: 'nav-count' }, count(state.report.findings.length)) : null)));
    $('sidebar-record').replaceChildren(el('div', { class: 'record-label' }, state.demo ? 'ILLUSTRATIVE WORKLOAD' : 'CURRENT WORKLOAD'), el('div', { class: 'record-name' }, text(state.report.image)), el('div', { class: 'record-digest', title: text(state.report.image_digest) }, short(state.report.image_digest, 35)), el('div', { class: 'row-meta' }, badge(state.report.reduced ? 'SARIF' : text(state.report.target_runtime.architecture), 'gray')));
    $('breadcrumb-title').textContent = routes.find(([path]) => path === route)[1];
    document.title = `SENTRYCHECK — ${routes.find(([path]) => path === route)[1]}${state.demo ? ' · Demo' : ''}`;
    $('main-content').replaceChildren();
    if (route === 'findings') parts[1] ? renderDetail(parts[1]) : renderFindings();
    else if (route === 'knowledge') renderKnowledge();
    else if (route === 'traces') renderTraces(parts[1]);
    else renderOverview();
    if (state.matrix) for (const anchor of document.querySelectorAll('a[href^="#"]')) {
      const href = anchor.getAttribute('href').split('?')[0];
      if (/^#(?:overview|findings|knowledge|traces|kb|timeline)(?:\/|$)/.test(href)) anchor.setAttribute('href', `${href}?runtime=${state.selectedRuntime}`);
    }
  }
  function fatal(error) {
    state.error = error instanceof Error ? error.message : String(error);
    notices();
    $('main-content').replaceChildren(el('section', { class: 'panel fatal-panel' }, body(icon('info'), el('h1', {}, 'This report could not be displayed'), el('p', {}, 'The embedded data is invalid or unsupported. No demo or clean result has been substituted.'), el('code', {}, state.error), button('Open a local report', () => $('report-file').click(), 'button-dark'))));
  }
  async function openFile(file) {
    if (!file) return;
    try {
      requireCondition(file.size <= 128 * 1024 * 1024, 'Report exceeds the 128 MiB local-file limit.');
      const input = JSON.parse(await file.text());
      const previousKb = state.availableKb || state.kb;
      loadPayload({ report: input, kb: previousKb }, { source: `Local file: ${file.name}`, uploaded: true });
      location.hash = 'overview';
    } catch (error) { state.error = error instanceof Error ? error.message : String(error); if (state.report) notices(); else fatal(error); }
    finally { $('report-file').value = ''; }
  }
  $('import-button').addEventListener('click', () => $('report-file').click());
  $('report-file').addEventListener('change', (event) => openFile(event.target.files?.[0]));
  window.addEventListener('hashchange', () => { try { render(); } catch (error) { fatal(error); } });
  let dragDepth = 0;
  window.addEventListener('dragenter', (event) => { if (Array.from(event.dataTransfer?.types || []).includes('Files')) { event.preventDefault(); dragDepth++; $('drop-overlay').hidden = false; } });
  window.addEventListener('dragover', (event) => { if (Array.from(event.dataTransfer?.types || []).includes('Files')) event.preventDefault(); });
  window.addEventListener('dragleave', () => { dragDepth = Math.max(0, dragDepth - 1); if (!dragDepth) $('drop-overlay').hidden = true; });
  window.addEventListener('drop', (event) => { event.preventDefault(); dragDepth = 0; $('drop-overlay').hidden = true; const file = event.dataTransfer?.files?.[0]; if (file) openFile(file); });
  document.querySelector('.skip-link').addEventListener('click', (event) => { event.preventDefault(); $('main-content').focus(); });
  try {
    const payload = JSON.parse($('sentrycheck-data').textContent);
    if (payload === ['__', 'SENTRYCHECK', '_DATA', '__'].join('')) loadPayload(JSON.parse($('sentrycheck-demo').textContent), { demo: true, source: 'Illustrative demo; not a real workload scan' });
    else loadPayload(payload);
  } catch (error) { fatal(error); }
})();
