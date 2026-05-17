import { Sheet, SheetContent, SheetHeader, SheetTitle, SheetDescription } from "@/components/ui/sheet";
import { Badge } from "@/components/ui/badge";
import type { TaskResult, Severity } from "@/lib/types";
import { OWASP_META } from "@/lib/types";
import { cn } from "@/lib/utils";

const SEV_CLR: Record<Severity, string> = {
  critical: "bg-[var(--sev-critical)]/15 text-[var(--sev-critical)] border-[var(--sev-critical)]/40",
  high: "bg-[var(--sev-high)]/15 text-[var(--sev-high)] border-[var(--sev-high)]/40",
  medium: "bg-[var(--sev-medium)]/15 text-[var(--sev-medium)] border-[var(--sev-medium)]/40",
  low: "bg-[var(--sev-low)]/15 text-[var(--sev-low)] border-[var(--sev-low)]/40",
  info: "bg-muted text-muted-foreground border-border",
};

interface EvidenceDrawerProps {
  finding: TaskResult | null;
  onClose: () => void;
}

function CodeBlock({ children }: { children: string }) {
  return (
    <pre className="overflow-auto rounded-md border border-border bg-surface px-3 py-2 font-mono text-[11px] leading-relaxed text-foreground/90">
      {children}
    </pre>
  );
}

function HeadersList({ headers }: { headers: Record<string, string> }) {
  const entries = Object.entries(headers);
  if (entries.length === 0) return <div className="text-[11px] text-muted-foreground">— none —</div>;
  return (
    <div className="space-y-0.5 font-mono text-[11px]">
      {entries.map(([k, v]) => (
        <div key={k} className="flex gap-2">
          <span className="text-muted-foreground">{k}:</span>
          <span className="truncate text-foreground/90">{v}</span>
        </div>
      ))}
    </div>
  );
}

export function EvidenceDrawer({ finding, onClose }: EvidenceDrawerProps) {
  return (
    <Sheet open={!!finding} onOpenChange={(o) => !o && onClose()}>
      <SheetContent
        side="right"
        className="w-full overflow-y-auto border-l border-border bg-background sm:max-w-xl"
      >
        {finding && (
          <>
            <SheetHeader className="space-y-3 border-b border-border pb-4">
              <div className="flex flex-wrap items-center gap-2">
                <span
                  className={cn(
                    "rounded border px-2 py-0.5 font-mono text-[10px] font-semibold uppercase",
                    SEV_CLR[finding.severity],
                  )}
                >
                  {finding.severity}
                </span>
                <Badge variant="outline" className="font-mono text-[10px]">
                  {OWASP_META[finding.vuln_category].code}
                </Badge>
                <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                  confidence {finding.confidence}
                </span>
              </div>
              <SheetTitle className="font-mono text-base">
                <span className="text-cyan">{finding.method}</span>{" "}
                <span className="text-foreground">{finding.endpoint}</span>
              </SheetTitle>
              <SheetDescription className="text-xs">
                {OWASP_META[finding.vuln_category].ref}
              </SheetDescription>
            </SheetHeader>

            <div className="space-y-5 pt-4">
              <section>
                <h3 className="mb-2 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                  Remediation
                </h3>
                <p className="text-xs leading-relaxed text-foreground/90">
                  {finding.remediation}
                </p>
              </section>

              <section>
                <h3 className="mb-2 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                  Request
                </h3>
                <CodeBlock>{`${finding.evidence.request.method} ${finding.evidence.request.url}`}</CodeBlock>
                <div className="mt-2">
                  <HeadersList headers={finding.evidence.request.headers} />
                </div>
                {finding.evidence.request.body && (
                  <div className="mt-2">
                    <CodeBlock>{finding.evidence.request.body}</CodeBlock>
                  </div>
                )}
              </section>

              <section>
                <h3 className="mb-2 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                  Response
                </h3>
                <div className="mb-2 flex items-center gap-3 font-mono text-[11px]">
                  <span
                    className={cn(
                      "rounded border px-1.5 py-0.5",
                      finding.evidence.response.status_code >= 500
                        ? "border-[var(--sev-critical)]/40 text-[var(--sev-critical)]"
                        : finding.evidence.response.status_code >= 400
                          ? "border-warning/40 text-warning"
                          : "border-success/40 text-success",
                    )}
                  >
                    {finding.evidence.response.status_code}
                  </span>
                  <span className="text-muted-foreground">
                    {finding.evidence.response.elapsed_ms} ms
                  </span>
                </div>
                <HeadersList headers={finding.evidence.response.headers} />
                <div className="mt-2">
                  <CodeBlock>{finding.evidence.response.body_excerpt || "(empty)"}</CodeBlock>
                </div>
              </section>

              <section className="border-t border-border pt-3">
                <div className="flex items-center justify-between font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                  <span>task {finding.task_id}</span>
                  <span>{new Date(finding.timestamp).toLocaleString()}</span>
                </div>
              </section>
            </div>
          </>
        )}
      </SheetContent>
    </Sheet>
  );
}
