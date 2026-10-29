"""Allowlisted diagnostics for intake baseline processes; never emit child logs."""
import json
import pathlib
import re
import subprocess
import time

STAGES = frozenset(('descriptor', 'schema-restore', 'service', 'page'))
PACKAGES = frozenset(('./internal/intake/descriptor', './internal/intake',
                      './internal/builtin', './internal/api', './internal/catalog',
                      './internal/store', './cmd/keep-server/app', './cmd/keep'))
TEST_DECL = re.compile(r'^func (Test[A-Za-z0-9_]+)\(\s*\w+ \*testing\.T\s*\)', re.M)
# Fixed fault signatures. Only the name and a count of matching lines are emitted.
SIGNATURES = (
    ('test-timeout', re.compile(r'panic: test timed out')),
    ('data-race', re.compile(r'WARNING: DATA RACE')),
    ('race-detected', re.compile(r'race detected during execution of test')),
    ('database-deadline', re.compile(r'database operation deadline exceeded')),
    ('context-deadline', re.compile(r'context deadline exceeded')),
    ('scratch-database', re.compile(r'create scratch database failed')),
    ('admin-pool', re.compile(r'open admin pool on scratch database failed')),
    ('connection-failed', re.compile(r'connection failed \(unclassified\)')),
    ('panic', re.compile(r'^panic:', re.M)),
    ('fatal-error', re.compile(r'^fatal error:', re.M)),
    ('build-failed', re.compile(r'\[build failed\]')),
    ('setup-failed', re.compile(r'\[setup failed\]')),
)
# `go test` prints a test's own failure messages as `    file_test.go:LINE: text`.
LOCATION = re.compile(r'^\s+([A-Za-z0-9_]+\.go):([0-9]+): (.*)$')
GO_STRING = re.compile(r'"((?:[^"\\\n]|\\.)*)"|`([^`\n]*)`')
# The one runtime-generated message that is safe and says why a test failed.
RUNTIME_MESSAGES = frozenset(('race detected during execution of test',))
SAFE_MESSAGE = re.compile(r'[\x20-\x7e]{1,200}')
ASSERTIONS_PER_TEST, ASSERTIONS_TOTAL = 4, 16
TEST_EVENT = re.compile(r'^\s*(?:--- (?:FAIL|SKIP):|=== RUN) +(Test[A-Za-z0-9_]+)(?:\s|$)', re.M)


def known_test_ids(cwd, packages):
    """Only source-declared top-level IDs; never emit arbitrary Go output text."""
    result = set()
    for package in packages:
        for source in (pathlib.Path(cwd) / package).glob('*_test.go'):
            result.update(TEST_DECL.findall(source.read_text()))
    return result


def signature_counts(text):
    """Counts of fixed fault signatures; never the matching text."""
    result = {}
    for name, pattern in SIGNATURES:
        count = len(pattern.findall(text))
        if count:
            result[name] = count
    return result


def _literals(source_line):
    found = set()
    for quoted, raw in GO_STRING.findall(source_line):
        found.add(raw if raw else quoted.replace('\\"', '"').replace('\\\\', '\\'))
    return found


def failed_assertions(text, failed_ids, cwd, packages):
    """Where each failed test failed, and why when the reason is fixed text.

    A message is emitted only if it is, character for character, a string
    literal on the very source line it is attributed to. Anything formatted at
    run time (an error value, a fetched field, a secret) cannot match a literal,
    so it is reduced to its location. Never a raw log line.
    """
    lines = text.splitlines()
    sources = {}
    for package in packages:
        for path in (pathlib.Path(cwd) / package).glob('*_test.go'):
            sources.setdefault(path.name, []).append(path)
    rows, truncated = [], False
    for test_id in failed_ids:
        fail = next((i for i, line in enumerate(lines)
                     if re.match(rf'^\s*--- FAIL: {re.escape(test_id)}(?:\s|$)', line)), None)
        if fail is None:
            continue
        begin = max((i for i in range(fail) if re.match(
            rf'^=== (?:RUN|CONT|PAUSE) +{re.escape(test_id)}(?:/|\s|$)', lines[i])), default=fail)
        end = fail + 1
        while end < len(lines) and lines[end].startswith('    '):
            end += 1
        seen = 0
        for line in lines[begin:end]:
            match = LOCATION.match(line)
            if not match:
                continue
            name, number, message = match.group(1), int(match.group(2)), match.group(3)
            # The location text comes from the child's output, and a multiline
            # message can forge it. File and line are emitted only after they
            # resolve against trusted source metadata; otherwise both are dropped.
            row = {'test': test_id, 'file': None, 'line': None, 'message': None}
            if name == 'testing.go':
                # Not in the repo, so its line cannot be checked and is never
                # echoed (a multiline message can forge any number): only the
                # one fixed runtime message is emitted, with no line.
                if message in RUNTIME_MESSAGES:
                    row.update(file='testing.go', message=message)
            else:
                candidates = sources.get(name, [])
                # A helper outside the selected packages, or a basename shared by
                # two packages, cannot be verified and is not located at all.
                if len(candidates) == 1:
                    source_lines = candidates[0].read_text().splitlines()
                    if 0 < number <= len(source_lines):
                        row['file'] = candidates[0].relative_to(pathlib.Path(cwd)).as_posix()
                        # The number came from child output and a multiline
                        # message can forge any in-range value: used only for the
                        # internal literal check above, never emitted.
                        if SAFE_MESSAGE.fullmatch(message) and message in _literals(source_lines[number - 1]):
                            row['message'] = message
            if seen == ASSERTIONS_PER_TEST or len(rows) == ASSERTIONS_TOTAL:
                truncated = True
                break
            rows.append(row)
            seen += 1
    return rows, truncated


def run_baseline(stage, command, *, cwd, env, timeout, prohibited_skips=()):
    if stage not in STAGES:
        raise ValueError('unknown intake baseline stage')
    packages = sorted(set(command) & PACKAGES)
    print(json.dumps({'baseline': stage, 'event': 'start', 'packages': packages,
                      'timeout_seconds': timeout}, sort_keys=True), flush=True)
    started = time.monotonic()
    code, output, failure = None, b'', None
    try:
        result = subprocess.run(command, cwd=cwd, env=env, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=timeout)
        code, output = result.returncode, result.stdout
    except subprocess.TimeoutExpired as exc:
        # Never print the exception: its command/output may contain secret values.
        output, failure = exc.output or b'', 'timeout'
    except OSError:
        failure = 'launch-error'
    report_baseline(stage, command, cwd=cwd, output=output, code=code,
                    elapsed=time.monotonic() - started, failure=failure,
                    prohibited_skips=prohibited_skips)
    if code is None:
        raise SystemExit(1)
    return result


def page_startup_snapshots(text):
    """Second fixed allowlist at the private Go-log -> CI-output boundary."""
    result = []
    fields = {'temporary': ('type', 'block_bytes', 'blocks', 'available_blocks'),
              'profile': ('type', 'block_bytes', 'blocks', 'available_blocks'),
              'shared_memory': ('type', 'block_bytes', 'blocks', 'available_blocks'),
              'cpu': ('nr_periods', 'nr_throttled', 'throttled_usec'),
              'memory': ('oom', 'oom_kill', 'high', 'max')}
    for line in text.splitlines():
        marker = 'page-startup-snapshot '
        if marker not in line:
            continue
        try:
            row = json.loads(line.split(marker, 1)[1])
        except (ValueError, TypeError):
            continue
        if not isinstance(row, dict) or row.get('phase') not in ('before', 'failure') or row.get('budget_ms') != 50:
            continue
        safe = {'phase': row['phase'], 'budget_ms': 50}
        for key in ('timed_out', 'unavailable'):
            safe[key] = row.get(key) is True
        for group, keys in fields.items():
            values = row.get(group)
            safe[group] = {k: v for k, v in values.items() if k in keys and type(v) is int and 0 <= v <= 2**53 - 1} if isinstance(values, dict) else {}
        safe['processes'] = []
        for process in (row.get('processes') or [])[:64] if isinstance(row.get('processes'), list) else []:
            if isinstance(process, dict):
                safe['processes'].append({'kind': process.get('kind') if process.get('kind') in ('chrome', 'chromium', 'chrome_crashpad_handler') else 'other',
                                          'state': process.get('state') if process.get('state') in ('R', 'S', 'D', 'Z', 'T', 't', 'I', 'X') else 'other'})
        result.append(safe)
        if len(result) == 2:
            break
    return result


def page_reason(text, code, cwd):
    """Reason codes and source locations are fixed metadata, not log excerpts."""
    if code == 0:
        reason = 'passed'
    elif 'panic: test timed out' in text:
        reason = 'test-timeout'
    elif any(marker in text for marker in ('database operation deadline exceeded',
                                           'context deadline exceeded',
                                           'page browser: navigation timeout')):
        reason = 'deadline'
    elif any(marker in text for marker in ('page browser: Chromium did not start',
                                           'page browser: Chromium is required')):
        reason = 'browser-launch'
    elif any(marker in text for marker in ('[build failed]', '[setup failed]',
                                           'no required module provides package',
                                           'cannot find package')):
        reason = 'build-or-dependency'
    elif any(marker in text for marker in ('create scratch database failed',
                                           'open admin pool on scratch database failed',
                                           'connection failed (unclassified)')):
        reason = 'database-unavailable'
    elif re.search(r'^panic:|^fatal error:', text, re.M):
        reason = 'process-crash'
    elif 'page browser failed' in text:
        # The test intentionally hides the Node error. Do not infer launch vs assertion.
        reason = 'browser-process-error'
    elif re.search(r'^\s*--- FAIL: TestIntakePageBrowserLifecycle(?:\s|$)', text, re.M):
        reason = 'test-failure-unclassified'
    else:
        reason = 'unclassified-process-failure'
    # Only this known repository file and an in-range line number may be emitted.
    source = pathlib.Path(cwd) / 'internal/builtin/intake_page_browser_test.go'
    line_count = len(source.read_text().splitlines())
    lines = sorted({int(line) for line in re.findall(
        r'^\s+intake_page_browser_test\.go:([0-9]+):', text, re.M)
        if 0 < int(line) <= line_count})
    return {'reason': reason, 'selected_test_ids': ['TestIntakePageBrowserLifecycle'],
            'source': 'internal/builtin/intake_page_browser_test.go',
            'source_lines': lines[:16], 'source_lines_truncated': len(lines) > 16}


def report_baseline(stage, command, *, cwd, output, code, elapsed,
                    failure=None, prohibited_skips=()):
    if stage not in STAGES:
        raise ValueError('unknown intake baseline stage')
    packages = sorted(set(command) & PACKAGES)
    known = known_test_ids(cwd, packages)
    text = output.decode(errors='replace')
    if failure is None:
        if re.search(r'^panic: test timed out after ', text, re.M):
            failure = 'timeout' if code != 0 else None
        if failure is None and any(marker in text for marker in prohibited_skips):
            failure = 'prohibited-skip'
        if failure is None and code != 0:
            failure = 'failed'
    observed = list(dict.fromkeys(name for name in TEST_EVENT.findall(text) if name in known))
    outcomes = {}
    for kind in ('FAIL', 'SKIP'):
        pattern = rf'^\s*--- {kind}: +(Test[A-Za-z0-9_]+)(?:\s|$)'
        ids = list(dict.fromkeys(name for name in re.findall(pattern, text, re.M) if name in known))
        key = 'failed' if kind == 'FAIL' else 'skipped'
        outcomes[key + '_test_ids'] = ids[:16]
        outcomes[key + '_test_id_count'] = len(ids)
        outcomes[key + '_test_ids_truncated'] = len(ids) > 16
    event = {'baseline': stage, 'event': 'end', 'seconds': round(elapsed, 3) if elapsed is not None else None,
             'exit_code': code, 'classification': failure or 'passed',
             'observed_test_ids': observed[-16:], 'observed_test_id_count': len(observed)}
    event.update(outcomes)
    if failure is not None:
        # Why it failed, not only which test: fixed signatures and, per failed
        # test, the failing assertion's verified source location and fixed message.
        event['signatures'] = signature_counts(text)
        rows, truncated = failed_assertions(text, outcomes['failed_test_ids'], cwd, packages)
        event['failed_assertions'] = rows
        event['failed_assertions_truncated'] = truncated
    if stage == 'page':
        event.update(page_reason(text, code, cwd))
        event['startup_snapshots'] = page_startup_snapshots(text)
    print(json.dumps(event, sort_keys=True), flush=True)


if __name__ == '__main__':
    import sys
    # Page wrapper supplies its private logfile after the unchanged Go command.
    # Diagnostics are observational; their return value never replaces Go's verdict.
    if len(sys.argv) != 3:
        raise SystemExit(2)
    report_baseline('page', ['./internal/builtin'], cwd=pathlib.Path(__file__).resolve().parent.parent,
                    output=pathlib.Path(sys.argv[1]).read_bytes(), code=int(sys.argv[2]), elapsed=None)
