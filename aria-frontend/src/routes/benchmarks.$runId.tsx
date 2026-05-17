import { useMemo, useState } from "react";
import { createFileRoute, useParams, Link } from "@tanstack/react-router";
import {
  ArrowLeft,
  Download,
  Loader2,
  Trophy,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Activity,
} from "lucide-react";
import { PageContainer } from "@/components/layout/PageContainer";
import { TopBar } from "@/components/layout/TopBar";
import { GroundTruthMatchTable } from "@/components/benchmark/GroundTruthMatchTable";
import { MetricsRadarChart } from "@/components/benchmark/MetricsRadarChart";
import { CategoryCoverageChart } from "@/components/benchmark/CategoryCoverageChart";
import { OWASPHeatmap } from "@/components/benchmark/OWASPHeatmap";
import { ScanDashboard } from "@/components/scan/ScanDashboard";
import { useBenchmarkRun } from "@/hooks/useBenchmark";
import type {
  BenchmarkRun,
  MatchStrategy,
  ModelBenchmarkResult,
  ModelName,
  OWASPCategory,
} from "@/lib/types";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/benchmarks/$runId")({
  component: BenchmarkRunPage,
});

type TabId = "overview" | "matching" | "analytics" | "raw" | "scan";

const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "matching", label: "Matching" },
  { id: "analytics", label: "Analytics" },
  { id: "scan", label: "Live Scan" },
  { id: "raw", label: "Raw Data" },
];

function BenchmarkRunPage() {
  const { runId } = useParams({ from: "/benchmarks/$runId" });
  const { run, isLoading, error, scanProgress, scanMessage, recompute } = useBenchmarkRun(runId);
  const isRunning = !run || run.status === "running" || run.status === "computing";
  const [tab, setTab] = useState<TabId>(isRunning ? "scan" : "overview");

  const exportJson = () => {
    if (!run) return;
    const blob = new Blob([JSON.stringify(run, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    const date = new Date(run.timestamp).toISOString().slice(0, 10);
    a.href = url;
    a.download = `aria-benchmark-${run.target}-${date}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <>
      <TopBar
        title={run ? `Benchmark — ${run.target_name}` : "Benchmark run"}
        subtitle={runId}
        actions={
          run && (
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={exportJson}
                className="inline-flex items-center gap-1.5 rounded-md border border-border bg-card px-3 py-1.5 font-mono text-[10px] uppercase tracking-widest text-muted-foreground hover:bg-surface-hover hover:text-foreground"
              >
                <Download className="h-3 w-3" />
                Export JSON
              </button>
            </div>
          )
        }
      />
      <PageContainer>
        <div className="mb-4 flex items-center gap-3">
          <Link
            to="/benchmarks"
            className="inline-flex items-center gap-2 font-mono text-[10px] uppercase tracking-widest text-muted-foreground hover:text-foreground"
          >
            <ArrowLeft className="h-3 w-3" />
            Back
          </Link>
          {run && (
            <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
              · {new Date(run.timestamp).toLocaleString()}
            </span>
          )}
        </div>

        {error && (
          <div className="mb-4 rounded-md border border-danger/40 bg-danger/10 p-3 font-mono text-xs text-danger">
            {error}
          </div>
        )}

        {!run ? (
          <div className="glass rounded-lg p-12 text-center text-xs text-muted-foreground">
            Run not found.
          </div>
        ) : (
          <>
            {/* Tabs */}
            <div className="mb-4 flex items-center justify-between border-b border-border">
              <div className="flex items-center gap-1">
                {TABS.filter((t) => t.id !== "scan" || !!run.scan_id).map((t) => (
                  <button
                    key={t.id}
                    type="button"
                    onClick={() => setTab(t.id)}
                    className={cn(
                      "flex items-center gap-1.5 border-b-2 px-4 py-2 font-mono text-[10px] uppercase tracking-widest transition-colors",
                      tab === t.id
                        ? "border-primary text-primary"
                        : "border-transparent text-muted-foreground hover:text-foreground",
                    )}
                  >
                    {t.id === "scan" && (
                      <Activity className={cn("h-3 w-3", (isRunning) && "animate-pulse")} />
                    )}
                    {t.label}
                    {t.id === "scan" && isRunning && (
                      <span className="ml-1 h-1.5 w-1.5 rounded-full bg-cyan animate-pulse" />
                    )}
                  </button>
                ))}
              </div>
              {/* Quick link to full scan page */}
              {run.scan_id && (
                <Link
                  to="/scan/$id"
                  params={{ id: run.scan_id }}
                  className="inline-flex items-center gap-1.5 pb-2 font-mono text-[10px] uppercase tracking-widest text-muted-foreground hover:text-foreground"
                >
                  <Activity className="h-3 w-3" />
                  Open scan
                </Link>
              )}
            </div>

            {tab === "overview" && (
              <OverviewTab
                run={run}
                isLoading={isLoading}
                progress={scanProgress}
                message={scanMessage}
                onViewScan={run.scan_id ? () => setTab("scan") : undefined}
              />
            )}
            {tab === "matching" && <MatchingTab run={run} onRecompute={recompute} />}
            {tab === "analytics" && <AnalyticsTab run={run} />}
            {tab === "scan" && run.scan_id && <ScanDashboard scanId={run.scan_id} />}
            {tab === "scan" && !run.scan_id && (
              <div className="rounded-lg border border-border bg-card/30 p-12 text-center font-mono text-xs text-muted-foreground">
                Scan ID not available for this run — it may have been launched in a different session.
              </div>
            )}
            {tab === "raw" && <RawDataTab run={run} />}
          </>
        )}
      </PageContainer>
    </>
  );
}

/* ──────────────────────────────────────────────────────────────────────────
 *  Overview tab
 * ────────────────────────────────────────────────────────────────────────── */

function OverviewTab({
  run,
  isLoading,
  progress,
  message,
  onViewScan,
}: {
  run: BenchmarkRun;
  isLoading: boolean;
  progress: number;
  message: string;
  onViewScan?: () => void;
}) {
  if (isLoading) {
    return (
      <div className="glass rounded-lg p-8">
        <div className="mb-4 flex items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Loader2 className="h-4 w-4 animate-spin text-primary" />
            <span className="font-mono text-xs uppercase tracking-widest text-foreground">
              {run.status === "computing" ? "Computing benchmark metrics..." : "Scan running"}
            </span>
          </div>
          {onViewScan && (
            <button
              type="button"
              onClick={onViewScan}
              className="inline-flex items-center gap-1.5 rounded-md border border-cyan/40 bg-cyan/10 px-3 py-1.5 font-mono text-[10px] uppercase tracking-widest text-cyan hover:bg-cyan/20"
            >
              <Activity className="h-3 w-3" />
              Live view
            </button>
          )}
        </div>
        <div className="mb-1 flex justify-between font-mono text-[10px] text-muted-foreground">
          <span>{message}</span>
          <span className="tabular-nums">{progress.toFixed(0)}%</span>
        </div>
        <div className="h-1.5 overflow-hidden rounded-full bg-card">
          <div
            className="h-full bg-primary transition-[width] duration-300"
            style={{ width: `${progress}%` }}
          />
        </div>
        <p className="mt-4 text-[11px] italic text-muted-foreground">
          Results will appear here automatically when the scan completes.
        </p>
      </div>
    );
  }

  if (run.status === "failed") {
    return (
      <div className="glass rounded-lg border border-danger/40 p-8 text-center">
        <XCircle className="mx-auto mb-2 h-6 w-6 text-danger" />
        <div className="font-mono text-xs uppercase tracking-widest text-danger">
          Scan failed
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Winner banner */}
      {run.summary.winner && run.results.length >= 2 && (
        <div className="glass flex items-center gap-4 rounded-lg border border-primary/40 p-5">
          <Trophy className="h-8 w-8 text-primary" />
          <div className="min-w-0 flex-1">
            <div className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
              Winner
            </div>
            <div className="font-mono text-base text-foreground">
              {prettyModel(run.summary.winner)}
            </div>
          </div>
          <div className="text-right">
            <div className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
              Best F1
            </div>
            <div className="font-mono text-2xl tabular-nums text-primary">
              {run.summary.best_f1.toFixed(3)}
            </div>
          </div>
        </div>
      )}

      {/* Model cards */}
      <div className={cn("grid gap-4", run.results.length > 1 ? "lg:grid-cols-2" : "")}>
        {run.results.map((r) => (
          <ModelResultCard key={r.model} result={r} totalGT={run.summary.total_ground_truth} />
        ))}
      </div>

      {/* Summary row */}
      <SummaryRow run={run} />
    </div>
  );
}

function ModelResultCard({ result, totalGT }: { result: ModelBenchmarkResult; totalGT: number }) {
  return (
    <div className="glass rounded-lg p-5">
      <div className="mb-3 flex items-center justify-between">
        <span className="font-mono text-sm text-foreground">{prettyModel(result.model)}</span>
        <span className={cn("font-mono text-3xl tabular-nums", f1Color(result.f1_score))}>
          {result.f1_score.toFixed(3)}
        </span>
      </div>
      <div className="mb-3 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
        F1 Score
      </div>

      <div className="mb-3 grid grid-cols-2 gap-3 border-y border-border py-3 font-mono text-[11px]">
        <Stat label="Precision" value={`${(result.precision * 100).toFixed(0)}%`} />
        <Stat label="Recall" value={`${(result.recall * 100).toFixed(0)}%`} />
        <Stat label="Avg latency" value={`${result.avg_latency_ms}ms`} />
        <Stat label="Fallbacks" value={String(result.fallback_count)} />
      </div>

      <div className="mb-3 flex items-center gap-2 font-mono text-[10px]">
        <span className="rounded border border-success/40 bg-success/10 px-2 py-0.5 text-success">
          TP {result.true_positives}
        </span>
        <span className="rounded border border-warning/40 bg-warning/10 px-2 py-0.5 text-warning">
          FP {result.false_positives}
        </span>
        <span className="rounded border border-danger/40 bg-danger/10 px-2 py-0.5 text-danger">
          FN {result.false_negatives}
        </span>
      </div>

      {/* TP proportion bar */}
      <div>
        <div className="mb-1 flex justify-between font-mono text-[9px] uppercase tracking-widest text-muted-foreground">
          <span>Coverage</span>
          <span className="tabular-nums text-foreground">
            {result.true_positives}/{totalGT}
          </span>
        </div>
        <div className="h-1.5 overflow-hidden rounded-full bg-card">
          <div
            className="h-full bg-success"
            style={{ width: `${totalGT > 0 ? (result.true_positives / totalGT) * 100 : 0}%` }}
          />
        </div>
      </div>
    </div>
  );
}

function SummaryRow({ run }: { run: BenchmarkRun }) {
  return (
    <div className="glass grid gap-4 rounded-lg p-5 sm:grid-cols-3">
      <div>
        <div className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
          Total ground truth
        </div>
        <div className="font-mono text-xl tabular-nums text-foreground">
          {run.summary.total_ground_truth}
        </div>
      </div>
      <div>
        <div className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
          Match strategy
        </div>
        <div className="font-mono text-sm uppercase text-foreground">
          {run.config.match_strategy}
        </div>
      </div>
      <div>
        <div className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
          Models tested
        </div>
        <div className="font-mono text-sm text-foreground">{run.results.length}</div>
      </div>

      <div className="sm:col-span-3">
        <div className="mb-2 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
          OWASP coverage
        </div>
        <div className="flex flex-wrap gap-2">
          <CoverageChips
            label="Fully covered"
            categories={run.summary.owasp_fully_covered}
            tone="success"
            icon={<CheckCircle2 className="h-3 w-3" />}
          />
          <CoverageChips
            label="Partial"
            categories={run.summary.owasp_partially_covered}
            tone="warning"
            icon={<AlertTriangle className="h-3 w-3" />}
          />
          <CoverageChips
            label="Missed"
            categories={run.summary.owasp_missed}
            tone="danger"
            icon={<XCircle className="h-3 w-3" />}
          />
        </div>
      </div>
    </div>
  );
}

function CoverageChips({
  label,
  categories,
  tone,
  icon,
}: {
  label: string;
  categories: OWASPCategory[];
  tone: "success" | "warning" | "danger";
  icon: React.ReactNode;
}) {
  if (categories.length === 0) return null;
  const cls = {
    success: "border-success/40 bg-success/10 text-success",
    warning: "border-warning/40 bg-warning/10 text-warning",
    danger: "border-danger/40 bg-danger/10 text-danger",
  }[tone];
  return (
    <div className="flex flex-wrap items-center gap-1">
      <span
        className={cn(
          "inline-flex items-center gap-1 rounded border px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-widest",
          cls,
        )}
      >
        {icon}
        {label}
      </span>
      {categories.map((c) => (
        <span
          key={c}
          className="rounded border border-border bg-card px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-widest text-foreground"
        >
          {c}
        </span>
      ))}
    </div>
  );
}

/* ──────────────────────────────────────────────────────────────────────────
 *  Matching tab
 * ────────────────────────────────────────────────────────────────────────── */

function MatchingTab({
  run,
  onRecompute,
}: {
  run: BenchmarkRun;
  onRecompute: (s: MatchStrategy) => void;
}) {
  const [activeModelIdx, setActiveModelIdx] = useState(0);
  const active = run.results[activeModelIdx];

  // Approximate "had victim token" — we don't store accounts, so we infer
  // from the absence of any matched finding that requires_victim_account.
  const hadVictimToken = useMemo(() => {
    if (!active) return false;
    return active.matched_findings.some((m) => m.ground_truth.requires_victim_account);
  }, [active]);

  if (!active) {
    return (
      <div className="glass rounded-lg p-8 text-center font-mono text-xs uppercase tracking-widest text-muted-foreground">
        No results yet — scan still running.
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Model selector + strategy toggle */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        {run.results.length > 1 ? (
          <div className="inline-flex rounded-md border border-border bg-card p-0.5">
            {run.results.map((r, i) => (
              <button
                key={r.model}
                type="button"
                onClick={() => setActiveModelIdx(i)}
                className={cn(
                  "rounded px-3 py-1.5 font-mono text-[10px] uppercase tracking-widest transition-colors",
                  activeModelIdx === i
                    ? "bg-primary text-primary-foreground"
                    : "text-muted-foreground hover:text-foreground",
                )}
              >
                {prettyModel(r.model)}
              </button>
            ))}
          </div>
        ) : (
          <div className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
            Model: {prettyModel(active.model)}
          </div>
        )}

        <div className="flex items-center gap-2">
          <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
            Strategy:
          </span>
          <div className="inline-flex rounded-md border border-border bg-card p-0.5">
            {(["strict", "relaxed"] as const).map((s) => (
              <button
                key={s}
                type="button"
                onClick={() => onRecompute(s)}
                className={cn(
                  "rounded px-3 py-1 font-mono text-[10px] uppercase tracking-widest transition-colors",
                  run.config.match_strategy === s
                    ? "bg-primary text-primary-foreground"
                    : "text-muted-foreground hover:text-foreground",
                )}
              >
                {s}
              </button>
            ))}
          </div>
        </div>
      </div>

      <GroundTruthMatchTable
        matched={active.matched_findings}
        missed={active.missed_ground_truth}
        falsePositives={active.false_positive_findings}
        hadVictimToken={hadVictimToken}
      />
    </div>
  );
}

/* ──────────────────────────────────────────────────────────────────────────
 *  Analytics tab
 * ────────────────────────────────────────────────────────────────────────── */

function AnalyticsTab({ run }: { run: BenchmarkRun }) {
  if (run.results.length === 0) {
    return (
      <div className="glass rounded-lg p-12 text-center font-mono text-xs uppercase tracking-widest text-muted-foreground">
        No results yet — scan still running.
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Row 1 — Radar + Bar chart */}
      <div className="grid gap-4 lg:grid-cols-2">
        <ChartCard title="Precision · Recall · F1 · Speed · Reliability">
          <MetricsRadarChart results={run.results} />
        </ChartCard>
        <ChartCard title="OWASP coverage per category">
          <CategoryCoverageChart results={run.results} />
        </ChartCard>
      </div>

      {/* Row 2 — Heatmap */}
      <ChartCard title="OWASP category coverage map">
        <OWASPHeatmap results={run.results} />
      </ChartCard>

      {/* Row 3 — Token & latency table */}
      <ChartCard title="Token & latency analysis">
        <div className="overflow-x-auto">
          <table className="w-full font-mono text-[11px]">
            <thead>
              <tr className="border-b border-border text-left text-muted-foreground">
                <th className="px-3 py-2 font-mono text-[10px] uppercase tracking-widest">Model</th>
                <th className="px-3 py-2 text-right font-mono text-[10px] uppercase tracking-widest">Tokens in</th>
                <th className="px-3 py-2 text-right font-mono text-[10px] uppercase tracking-widest">Tokens out</th>
                <th className="px-3 py-2 text-right font-mono text-[10px] uppercase tracking-widest">Avg latency</th>
                <th className="px-3 py-2 text-right font-mono text-[10px] uppercase tracking-widest">Fallbacks</th>
                <th className="px-3 py-2 font-mono text-[10px] uppercase tracking-widest">Cost</th>
              </tr>
            </thead>
            <tbody>
              {run.results.map((r) => (
                <tr key={r.model} className="border-b border-border/40 text-foreground">
                  <td className="px-3 py-2">{prettyModel(r.model)}</td>
                  <td className="px-3 py-2 text-right tabular-nums">{r.total_tokens_in.toLocaleString()}</td>
                  <td className="px-3 py-2 text-right tabular-nums">{r.total_tokens_out.toLocaleString()}</td>
                  <td className="px-3 py-2 text-right tabular-nums">{r.avg_latency_ms} ms</td>
                  <td className="px-3 py-2 text-right tabular-nums">{r.fallback_count}</td>
                  <td className="px-3 py-2 text-muted-foreground">local inference</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </ChartCard>
    </div>
  );
}

function ChartCard({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="glass rounded-lg p-4">
      <div className="mb-3 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
        {title}
      </div>
      {children}
    </div>
  );
}

/* ──────────────────────────────────────────────────────────────────────────
 *  Raw Data tab
 * ────────────────────────────────────────────────────────────────────────── */

function RawDataTab({ run }: { run: BenchmarkRun }) {
  const json = useMemo(() => JSON.stringify(run, null, 2), [run]);
  const [copied, setCopied] = useState(false);

  const copy = () => {
    void navigator.clipboard.writeText(json);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div className="glass overflow-hidden rounded-lg">
      <div className="flex items-center justify-between border-b border-border px-4 py-2">
        <div className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
          Full BenchmarkRun JSON · {json.length.toLocaleString()} chars
        </div>
        <button
          type="button"
          onClick={copy}
          className="rounded-md border border-border bg-card px-3 py-1 font-mono text-[10px] uppercase tracking-widest text-muted-foreground hover:bg-surface-hover hover:text-foreground"
        >
          {copied ? "✓ Copied" : "Copy"}
        </button>
      </div>
      <pre className="max-h-[600px] overflow-auto bg-[oklch(0.06_0.02_260)] p-4 font-mono text-[10px] leading-relaxed text-foreground">
        {json}
      </pre>
    </div>
  );
}

/* ──────────────────────────────────────────────────────────────────────────
 *  Utility helpers
 * ────────────────────────────────────────────────────────────────────────── */

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="font-mono text-[9px] uppercase tracking-widest text-muted-foreground">
        {label}
      </div>
      <div className="font-mono tabular-nums text-foreground">{value}</div>
    </div>
  );
}

function prettyModel(m: ModelName): string {
  switch (m) {
    case "foundation-sec-reasoning":
      return "Foundation-Sec Reasoning";
    case "foundation-sec-instruct":
      return "Foundation-Sec Instruct";
    case "qwen2.5":
      return "Qwen2.5";
    case "both":
      return "Both models";
  }
}

function f1Color(f1: number): string {
  if (f1 >= 0.8) return "text-success";
  if (f1 >= 0.5) return "text-warning";
  return "text-danger";
}
