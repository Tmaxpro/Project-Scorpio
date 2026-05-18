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
    <pre className="overflow-auto ui-codeblock text-[11px] leading-relaxed text-foreground/90">
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
                    "ui-chip ui-chip-sm font-semibold",
                    SEV_CLR[finding.severity],
                  )}
                >
                  {finding.severity}
                </span>
                <Badge variant="outline" className="ui-label">
                  {OWASP_META[finding.vuln_category].code}
                </Badge>
                <span className="ui-label">
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
                <h3 className="ui-label mb-2">
                  Remediation
                </h3>
                <p className="text-xs leading-relaxed text-foreground/90">
                  {finding.remediation}
                </p>
              </section>

              <section>
                <h3 className="ui-label mb-2">
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
                <h3 className="ui-label mb-2">
                  Response
                </h3>
                <div className="mb-2 flex items-center gap-3 font-mono text-[11px]">
                  <span
                    className={cn(
                      "ui-chip ui-chip-xs",
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
                <div className="flex items-center justify-between ui-label">
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
