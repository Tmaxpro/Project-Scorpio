import { ShieldCheck } from "lucide-react";
import type { Severity, TaskResult } from "@/lib/types";
import { OWASP_META } from "@/lib/types";
import { cn } from "@/lib/utils";

const SEV_STYLES: Record<Severity, { chip: string; glow: string; label: string }> = {
  critical: {
    chip: "bg-[var(--sev-critical)]/15 text-[var(--sev-critical)] border-[var(--sev-critical)]/40",
    glow: "glow-critical",
    label: "CRITICAL",
  },
  high: {
    chip: "bg-[var(--sev-high)]/15 text-[var(--sev-high)] border-[var(--sev-high)]/40",
    glow: "glow-high",
    label: "HIGH",
  },
  medium: {
    chip: "bg-[var(--sev-medium)]/15 text-[var(--sev-medium)] border-[var(--sev-medium)]/40",
    glow: "glow-medium",
    label: "MEDIUM",
  },
  low: {
    chip: "bg-[var(--sev-low)]/15 text-[var(--sev-low)] border-[var(--sev-low)]/40",
    glow: "glow-low",
    label: "LOW",
  },
  info: {
    chip: "bg-muted text-muted-foreground border-border",
    glow: "",
    label: "INFO",
  },
};

interface SeverityCountersProps {
  bySeverity: Record<Severity, number>;
}

export function SeverityCounters({ bySeverity }: SeverityCountersProps) {
  const order: Severity[] = ["critical", "high", "medium", "low", "info"];
  return (
    <div className="grid grid-cols-5 gap-2">
      {order.map((s) => {
        const v = bySeverity[s] ?? 0;
        const st = SEV_STYLES[s];
        return (
          <div
            key={s}
            className={cn(
              "glass rounded-md px-3 py-2.5 transition-all",
              v > 0 && st.glow,
            )}
          >
            <div className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
              {st.label}
            </div>
            <div
              className={cn(
                "mt-0.5 font-mono text-2xl font-semibold tabular-nums",
                v > 0 ? st.chip.split(" ")[1] : "text-foreground/40",
              )}
            >
              {v}
            </div>
          </div>
        );
      })}
    </div>
  );
}

interface FindingsListProps {
  findings: TaskResult[];
  onSelect?: (f: TaskResult) => void;
}

export function FindingsList({ findings, onSelect }: FindingsListProps) {
  return (
    <div className="glass flex h-full flex-col overflow-hidden rounded-lg">
      <div className="flex items-center justify-between border-b border-border px-3 py-2">
        <h3 className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
          Findings
        </h3>
        <span className="font-mono text-[10px] text-muted-foreground">
          {findings.length} total
        </span>
      </div>
      <div className="flex-1 overflow-auto">
        {findings.length === 0 ? (
          <div className="flex h-full min-h-32 flex-col items-center justify-center gap-2 px-4 py-8 text-center">
            <ShieldCheck className="h-8 w-8 text-success/70" strokeWidth={1.25} />
            <div className="font-mono text-[11px] uppercase tracking-widest text-muted-foreground">
              No findings yet
            </div>
            <div className="text-[11px] text-muted-foreground/80">
              Scanner is probing endpoints — vulnerabilities will appear here in real time.
            </div>
          </div>
        ) : (
          <ul className="divide-y divide-border">
            {findings.map((f) => {
              const st = SEV_STYLES[f.severity];
              return (
                <li
                  key={f.task_id}
                  onClick={() => onSelect?.(f)}
                  className="flex cursor-pointer items-start gap-3 px-3 py-2.5 hover:bg-surface-hover/40"
                >
                  <span
                    className={cn(
                      "mt-0.5 shrink-0 rounded border px-1.5 py-0.5 font-mono text-[10px] font-semibold",
                      st.chip,
                    )}
                  >
                    {st.label}
                  </span>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 font-mono text-xs">
                      <span className="text-cyan">{f.method}</span>
                      <span className="truncate text-foreground">{f.endpoint}</span>
                    </div>
                    <div className="text-[11px] text-muted-foreground">
                      {OWASP_META[f.vuln_category].ref} · confidence {f.confidence}
                    </div>
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </div>
    </div>
  );
}
