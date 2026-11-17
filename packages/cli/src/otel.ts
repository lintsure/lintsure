// lintsure export --otlp-json: turns the local activity log (.lintsure/activity.jsonl, written by the plugin's guards
// and end-of-task scans) into an OpenTelemetry traces file (OTLP/JSON) a team can load into its own observability
// tool. Written to a file only; nothing is sent anywhere. Names follow the OpenTelemetry GenAI conventions
// (gen_ai.operation.name, gen_ai.conversation.id, gen_ai.tool.name) plus Lintsure's own lintsure.* fields.
// The log holds no code or command text, so the spans can't carry any either.
import { createHash } from "node:crypto";

export interface ActivityRow { at: string; type: "catch" | "decision" | "scan"; session?: string | null; kind?: string; rule?: string;
  file?: string; line?: number; outcome?: string; scope?: string; open?: number; gap?: number; partial?: number; policy?: string; rules?: string }

const hex = (s: string, n: number) => createHash("sha256").update(s).digest("hex").slice(0, n);
const nanos = (iso: string) => `${BigInt(Date.parse(iso) || 0) * 1_000_000n}`;
type Attr = { key: string; value: { stringValue: string } | { intValue: string } };
const attrs = (o: Record<string, string | number | undefined | null>): Attr[] => Object.entries(o).filter(([, v]) => v != null && v !== "")
  .map(([key, v]) => ({ key, value: typeof v === "number" ? { intValue: String(v) } : { stringValue: String(v) } }));

/** One trace per session (reads OTEL_SERVICE_NAME for the service name): an invoke_agent span covering it, and one child span per catch, decision or scan. Pure. */
export function toOtlp(rows: ActivityRow[], version: string) {
  const bySession = new Map<string, ActivityRow[]>();
  for (const r of rows) { const k = r.session || "no-session"; (bySession.get(k) ?? bySession.set(k, []).get(k)!).push(r); }
  const spans: unknown[] = [];
  for (const [session, list] of bySession) {
    const traceId = hex(`trace:${session}`, 32), rootId = hex(`root:${session}`, 16);
    const times = list.map((r) => r.at).sort();
    spans.push({ traceId, spanId: rootId, name: "invoke_agent", kind: 1, startTimeUnixNano: nanos(times[0]), endTimeUnixNano: nanos(times[times.length - 1]),
      attributes: attrs({ "gen_ai.operation.name": "invoke_agent", "gen_ai.agent.name": "coding agent (guarded by Lintsure)", "gen_ai.conversation.id": session }) });
    list.forEach((r, i) => {
      const base = { traceId, spanId: hex(`span:${session}:${i}:${r.at}`, 16), parentSpanId: rootId, kind: 1, startTimeUnixNano: nanos(r.at), endTimeUnixNano: nanos(r.at) };
      // Current semconv names plus the older ones many tools still read.
      const code = { "code.file.path": r.file, "code.line.number": r.line, "code.filepath": r.file, "code.lineno": r.line };
      if (r.type === "catch") spans.push({ ...base, name: `execute_tool lintsure.guard.${r.kind}`, attributes: attrs({ "gen_ai.operation.name": "execute_tool",
        "gen_ai.tool.name": `lintsure.guard.${r.kind}`, "gen_ai.conversation.id": session, "lintsure.rule.id": r.rule, "lintsure.decision": r.outcome, ...code }) });
      else if (r.type === "decision") spans.push({ ...base, name: "lintsure.decision", attributes: attrs({ "gen_ai.conversation.id": session, "lintsure.decision": r.scope, "lintsure.rule.id": r.rule, ...code }) });
      else spans.push({ ...base, name: "lintsure.scan", attributes: attrs({ "gen_ai.conversation.id": session, "lintsure.policy.fingerprint": r.policy, "lintsure.rules.version": r.rules,
        "lintsure.findings.open": r.open, "lintsure.findings.gap": r.gap, "lintsure.findings.partial": r.partial }) });
    });
  }
  return { resourceSpans: [{ resource: { attributes: attrs({ "service.name": process.env.OTEL_SERVICE_NAME || "lintsure", "service.version": version }) }, scopeSpans: [{ scope: { name: "lintsure", version }, spans }] }] };
}

/** Reads activity.jsonl lines, skipping any it can't parse. Pure. */
export function parseActivity(text: string): ActivityRow[] {
  return text.split(/\r?\n/).flatMap((l) => { try { const r = JSON.parse(l); return r && r.at && r.type ? [r as ActivityRow] : []; } catch { return []; } });
}
