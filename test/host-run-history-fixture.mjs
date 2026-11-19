// The door's recent record of a doorkeeper case (apps/api/test/fixtures/
// host-run-review-cases.json, field `history`), in the shape the API builds
// from its job table (hostRunHistoryFromJobs, card t_f9c7dcec): times in
// minutes before now become ISO stamps, `manifestFrom` takes another case's
// manifest. Without `history` the record is empty. Used by
// test/host-run-review-live.mjs and apps/api/test/host-run.test.ts.
export function caseHistory(item, cases, parseHostRunManifest, now = new Date()) {
  const at = (minutes) => (typeof minutes === "number" ? new Date(now.getTime() - minutes * 60_000).toISOString() : null);
  const manifestOf = (run) => {
    const raw = run.manifestFrom ? cases.find((other) => other.id === run.manifestFrom)?.manifest : run.manifest;
    return raw ? parseHostRunManifest("```host-run\n" + JSON.stringify(raw) + "\n```") : null;
  };
  const engineLines = (engines) => Object.entries(engines || {}).map(([role, engine]) => `${role} ${engine.name}/${engine.model}${engine.notbetrieb ? " NOTBETRIEB" : ""}`);
  const history = item.history || { runs: [], notbetrieb: [] };
  return {
    now: now.toISOString(),
    hours: 24,
    runs: history.runs.map((run) => ({
      jobId: run.jobId, orderedAt: at(run.orderedMinutesAgo), startedAt: at(run.startedMinutesAgo), finishedAt: at(run.finishedMinutesAgo),
      status: run.status, engines: engineLines(run.engines), manifest: manifestOf(run),
    })),
    notbetrieb: history.notbetrieb.map((job) => ({ jobId: job.jobId, orderedAt: at(job.orderedMinutesAgo), status: job.status, roles: job.roles })),
  };
}
