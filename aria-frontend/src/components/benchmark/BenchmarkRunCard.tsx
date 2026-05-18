import { Link } from "@tanstack/react-router";
import { ArrowRight, Trash2 } from "lucide-react";
import { useNavigate } from "@tanstack/react-router";
import type { BenchmarkRun } from "@/lib/types";
import { deleteBenchmarkRun } from "@/lib/api";
import { cn } from "@/lib/utils";

interface BenchmarkRunCardProps {
  run: BenchmarkRun;
  onDeleted?: () => void;
}

const DIFFICULTY_BADGE: Record<string, string> = {
  vampi: "border-success/40 bg-success/10 text-success",
  dvapi: "border-warning/40 bg-warning/10 text-warning",
  crapi: "border-danger/40 bg-danger/10 text-danger",
};

const STATUS_BADGE: Record<BenchmarkRun["status"], string> = {
  running: "border-primary/40 bg-primary/10 text-primary",
  computing: "border-primary/40 bg-primary/10 text-primary",
  completed: "border-success/40 bg-success/10 text-success",
  failed: "border-danger/40 bg-danger/10 text-danger",
};

function f1Color(f1: number): string {
  if (f1 >= 0.8) return "text-success";
  if (f1 >= 0.5) return "text-warning";
  return "text-danger";
}

export function BenchmarkRunCard({ run, onDeleted }: BenchmarkRunCardProps) {
  const navigate = useNavigate();
  const totalFound = run.results.reduce((s, r) => s + r.true_positives, 0);
  const totalGT = run.summary.total_ground_truth;
  const coveragePct = totalGT > 0 ? (totalFound / totalGT) * 100 : 0;

  const handleDelete = async (e: React.MouseEvent) => {
    e.stopPropagation();
    e.preventDefault();
    if (window.confirm(`Delete this benchmark run for ${run.target_name}?`)) {
      await deleteBenchmarkRun(run.run_id);
      onDeleted?.();
    }
  };

  const handleGoToScan = (e: React.MouseEvent) => {
    e.stopPropagation();
    e.preventDefault();
    if (run.scan_id) {
      navigate({ to: "/scan/$id", params: { id: run.scan_id } });
    }
  };

  const handleCardClick = () => {
    navigate({ to: "/benchmarks/$runId", params: { runId: run.run_id } });
  };

  return (
    <div
      onClick={handleCardClick}
      className="glass flex items-center gap-4 rounded-lg border border-border p-4 transition-colors hover:border-primary/40 cursor-pointer"
    >
      {/* Date column */}
      <div className="w-28 shrink-0 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
        {new Date(run.timestamp).toLocaleDateString()}
      </div>

      {/* Target column */}
      <div className="w-32 shrink-0">
        <div className="flex items-center gap-2">
          <span className="font-mono text-xs text-foreground">{run.target_name}</span>
          <span
            className={cn(
              "rounded border px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-widest",
              DIFFICULTY_BADGE[run.target],
            )}
          >
            {run.target}
          </span>
        </div>
      </div>

      {/* Models column */}
      <div className="w-40 shrink-0">
        <div className="flex flex-wrap gap-1">
          {run.results.length === 0 ? (
            <span className="font-mono text-[10px] text-muted-foreground">—</span>
          ) : (
            run.results.map((r) => (
              <span
                key={r.model}
                className="rounded border border-border bg-card px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-widest text-muted-foreground"
              >
                {r.model.replace("foundation-sec-", "F-Sec-").replace("qwen2.5", "Qwen2.5")}
              </span>
            ))
          )}
        </div>
      </div>

      {/* Best F1 column */}
      <div className="w-24 shrink-0 text-center">
        <div className="font-mono text-[9px] uppercase tracking-widest text-muted-foreground">
          Best F1
        </div>
        <div className={cn("font-mono text-lg tabular-nums", f1Color(run.summary.best_f1))}>
          {run.summary.best_f1 > 0 ? run.summary.best_f1.toFixed(2) : "—"}
        </div>
      </div>

      {/* Coverage column */}
      <div className="min-w-0 flex-1">
        <div className="mb-1 flex items-center justify-between gap-2">
          <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
            Coverage
          </span>
          <span className="font-mono text-[10px] tabular-nums text-foreground">
            {totalFound}/{totalGT}
          </span>
        </div>
        <div className="h-1.5 overflow-hidden rounded-full bg-card">
          <div
            className="h-full bg-primary transition-[width] duration-300"
            style={{ width: `${coveragePct}%` }}
          />
        </div>
      </div>

      {/* Status badge */}
      <div className="w-24 shrink-0 text-center">
        <span
          className={cn(
            "inline-block rounded border px-2 py-0.5 font-mono text-[9px] uppercase tracking-widest",
            STATUS_BADGE[run.status],
          )}
        >
          {run.status}
        </span>
      </div>

      {/* Actions */}
      <div className="flex shrink-0 items-center gap-1">
        <button
          type="button"
          onClick={handleDelete}
          aria-label="Delete run"
          className="rounded p-1.5 text-muted-foreground hover:bg-danger/10 hover:text-danger"
        >
          <Trash2 className="h-3.5 w-3.5" />
        </button>
        <button
          type="button"
          onClick={handleGoToScan}
          aria-label="View raw scan"
          className="rounded p-1.5 text-muted-foreground hover:bg-surface-hover/60 hover:text-primary"
        >
          <ArrowRight className="h-4 w-4" />
        </button>
      </div>
    </div>
  );
}
