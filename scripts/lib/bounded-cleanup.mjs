// Attempt every owned cleanup step under its own deadline. A cleanup failure
// never replaces the primary error; it is reported only when nothing else failed.
// A step is a function under the shared deadline, or {run, ms} when it has a
// bounded procedure of its own that needs longer.
export async function boundedCleanup(steps, {primary, ms = 2000} = {}) {
  let failed = false;
  for (const step of steps) {
    const run = typeof step === 'function' ? step : step.run;
    const deadline = typeof step === 'function' ? ms : step.ms;
    let timer;
    try {
      await Promise.race([Promise.resolve().then(run),
        new Promise((_, reject) => {timer = setTimeout(() => reject(new Error('cleanup deadline')), deadline);})]);
    } catch { failed = true; }
    finally { clearTimeout(timer); }
  }
  if (!failed) return;
  if (primary === undefined) throw Object.assign(new Error('Intake browser cleanup incomplete'), {code:'CLEANUP_BOUNDARY'});
  process.stderr.write(JSON.stringify({event:'intake-browser-cleanup-failed', code:'CLEANUP_BOUNDARY'}) + '\n');
}
