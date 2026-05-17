import { useState } from "react";
import { ChevronDown, ChevronUp, AlertTriangle } from "lucide-react";
import type {
  GroundTruthEntry,
  MatchedFinding,
  Severity,
  TaskResult,
} from "@/lib/types";
import { cn } from "@/lib/utils";

interface Props {
  matched: MatchedFinding[];
  missed: GroundTruthEntry[];
  falsePositives: TaskResult[];
  /** When true, missed entries needing user2 token are flagged. */
  hadVictimToken: boolean;
}

const SEVERITY_STYLE: Record<Severity, string> = {
  critical: "border-danger/60 bg-danger/15 text-danger",
  high: "border-danger/40 bg-danger/10 text-danger",
  medium: "border-warning/40 bg-warning/10 text-warning",
  low: "border-success/40 bg-success/10 text-success",
  info: "border-border bg-card text-muted-foreground",
};

const MATCH_TYPE_STYLE = {
  exact: { color: "border-success/40 bg-success/10 text-success", label: "Exact match" },
  partial: { color: "border-warning/40 bg-warning/10 text-warning", label: "Partial match" },
  category_only: { color: "border-danger/40 bg-danger/10 text-danger", label: "Category only" },
} as const;

export function GroundTruthMatchTable({ matched, missed, falsePositives, hadVictimToken }: Props) {
  return (
    <div className="grid gap-4 lg:grid-cols-3">
      {/* True Positives */}
      <Column
        title="True positives"
        count={matched.length}
        tone="success"
        emptyMessage="No findings matched ground truth."
      >
        {matched.map((m) => (
          <TruePositiveCard key={m.ground_truth.id} match={m} />
        ))}
      </Column>

      {/* False Negatives */}
      <Column
        title="False negatives (missed)"
        count={missed.length}
        tone="danger"
        emptyMessage="ARIA found everything in the ground truth!"
      >
        {missed.map((gt) => (
          <FalseNegativeCard key={gt.id} gt={gt} hadVictimToken={hadVictimToken} />
        ))}
      </Column>

      {/* False Positives */}
      <Column
        title="False positives"
        count={falsePositives.length}
        tone="warning"
        emptyMessage="No false positives — clean run."
      >
        {falsePositives.map((f) => (
          <FalsePositiveCard key={f.task_id} finding={f} />
        ))}
      </Column>
    </div>
  );
}

function Column({
  title,
  count,
  tone,
  emptyMessage,
  children,
}: {
  title: string;
  count: number;
  tone: "success" | "danger" | "warning";
  emptyMessage: string;
  children: React.ReactNode;
}) {
  const ring = {
    success: "border-success/30",
    danger: "border-danger/30",
    warning: "border-warning/30",
  }[tone];
  const text = {
    success: "text-success",
    danger: "text-danger",
    warning: "text-warning",
  }[tone];

  return (
    <div className={cn("glass overflow-hidden rounded-lg border", ring)}>
      <div className={cn("flex items-center justify-between border-b border-border px-4 py-2", text)}>
        <span className="font-mono text-[10px] uppercase tracking-widest">{title}</span>
        <span className="font-mono text-sm tabular-nums">{count}</span>
      </div>
      <div className="max-h-[600px] space-y-2 overflow-y-auto p-3">
        {count === 0 ? (
          <p className="rounded-md border border-dashed border-border bg-card/30 p-4 text-center font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
            {emptyMessage}
          </p>
        ) : (
          children
        )}
      </div>
    </div>
  );
}

function TruePositiveCard({ match }: { match: MatchedFinding }) {
  const [open, setOpen] = useState(false);
  const m = MATCH_TYPE_STYLE[match.match_type];

  return (
    <div className="rounded-md border border-border bg-card/40 p-3">
      <div className="mb-1 flex flex-wrap items-center gap-1.5">
        <CategoryBadge cat={match.ground_truth.vuln_category} />
        <SeverityBadge sev={match.ground_truth.severity} />
        <span className={cn("rounded border px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-widest", m.color)}>
          {m.label}
        </span>
        <span className="ml-auto font-mono text-[9px] tabular-nums text-muted-foreground">
          {(match.match_score * 100).toFixed(0)}%
        </span>
      </div>
      <p className="mb-2 text-[11px] text-muted-foreground">{match.ground_truth.description}</p>
      <div className="rounded border border-border bg-background px-2 py-1 font-mono text-[10px] text-foreground">
        <span className="text-muted-foreground">↳ Found as: </span>
        <span className="text-success">{match.aria_finding.method}</span>{" "}
        <span>{match.aria_finding.endpoint}</span>
      </div>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="mt-2 flex items-center gap-1 font-mono text-[9px] uppercase tracking-widest text-muted-foreground hover:text-foreground"
      >
        {open ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
        Evidence
      </button>
      {open && (
        <div className="mt-2 space-y-1 rounded border border-border bg-background p-2 font-mono text-[10px]">
          <div className="text-muted-foreground">Remediation:</div>
          <div className="text-foreground">{match.aria_finding.remediation || "—"}</div>
          <div className="mt-1 text-muted-foreground">Response excerpt:</div>
          <pre className="overflow-x-auto whitespace-pre-wrap text-[10px] text-foreground">
            {match.aria_finding.evidence.response.body_excerpt || "(no body captured)"}
          </pre>
        </div>
      )}
    </div>
  );
}

function FalseNegativeCard({ gt, hadVictimToken }: { gt: GroundTruthEntry; hadVictimToken: boolean }) {
  const skipped = gt.requires_victim_account && !hadVictimToken;
  return (
    <div
      className={cn(
        "rounded-md border bg-card/40 p-3",
        skipped ? "border-warning/40" : "border-border",
      )}
    >
      <div className="mb-1 flex flex-wrap items-center gap-1.5">
        <CategoryBadge cat={gt.vuln_category} />
        <SeverityBadge sev={gt.severity} />
        {skipped && (
          <span className="inline-flex items-center gap-1 rounded border border-warning/40 bg-warning/10 px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-widest text-warning">
            <AlertTriangle className="h-2.5 w-2.5" />
            Skipped — no victim token
          </span>
        )}
      </div>
      <p className="mb-2 text-[11px] text-muted-foreground">{gt.description}</p>
      <div className="rounded border border-border bg-background px-2 py-1 font-mono text-[10px] text-foreground">
        <span className="text-danger">{gt.method}</span> <span>{gt.endpoint}</span>
      </div>
      <p className="mt-2 font-mono text-[10px] italic text-muted-foreground">
        Hint: {gt.exploit_hint}
      </p>
    </div>
  );
}

function FalsePositiveCard({ finding }: { finding: TaskResult }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="rounded-md border border-warning/30 bg-card/40 p-3">
      <div className="mb-1 flex flex-wrap items-center gap-1.5">
        <CategoryBadge cat={finding.vuln_category} />
        <SeverityBadge sev={finding.severity} />
      </div>
      <div className="rounded border border-border bg-background px-2 py-1 font-mono text-[10px] text-foreground">
        <span className="text-warning">{finding.method}</span> <span>{finding.endpoint}</span>
      </div>
      <p className="mt-2 text-[10px] italic text-muted-foreground">
        Not in ground truth — may be a real vuln or a hallucination.
      </p>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="mt-2 flex items-center gap-1 font-mono text-[9px] uppercase tracking-widest text-muted-foreground hover:text-foreground"
      >
        {open ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
        Evidence
      </button>
      {open && (
        <pre className="mt-2 overflow-x-auto whitespace-pre-wrap rounded border border-border bg-background p-2 font-mono text-[10px] text-foreground">
          {finding.evidence.response.body_excerpt || "(no body captured)"}
        </pre>
      )}
    </div>
  );
}

function CategoryBadge({ cat }: { cat: string }) {
  return (
    <span className="rounded border border-primary/40 bg-primary/10 px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-widest text-primary">
      {cat}
    </span>
  );
}

function SeverityBadge({ sev }: { sev: Severity }) {
  return (
    <span className={cn("rounded border px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-widest", SEVERITY_STYLE[sev])}>
      {sev}
    </span>
  );
}

