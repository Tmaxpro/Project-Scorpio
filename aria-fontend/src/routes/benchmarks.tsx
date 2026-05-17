import { useEffect, useMemo, useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { GitCompare, Zap } from "lucide-react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Radar,
  RadarChart,
  PolarAngleAxis,
  PolarGrid,
  PolarRadiusAxis,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { PageContainer } from "@/components/layout/PageContainer";
import { TopBar } from "@/components/layout/TopBar";
import { EmptyState } from "@/components/ui/empty-state";
import { getBenchmarkRuns } from "@/lib/api";
import { mockBenchmarks } from "@/lib/mock";
import type { BenchmarkRun } from "@/lib/types";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/benchmarks")({
  component: BenchmarksPage,
});

const MODEL_COLORS: Record<string, string> = {
  "Foundation-Sec-8B-Reasoning": "var(--cyan)",
  "Qwen2.5-7B": "var(--violet)",
};

function BenchmarksPage() {
  const [runs, setRuns] = useState<BenchmarkRun[]>([]);
  const [isMock, setIsMock] = useState(false);
  const [loading, setLoading] = useState(true);
  const [activeRunId, setActiveRunId] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const data = await getBenchmarkRuns();
        if (!cancelled) {
          setRuns(data);
          setActiveRunId(data[0]?.run_id ?? null);
          setIsMock(false);
        }
      } catch {
        if (!cancelled) {
          setRuns(mockBenchmarks);
          setActiveRunId(mockBenchmarks[0]?.run_id ?? null);
          setIsMock(true);
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const activeRun = useMemo(
    () => runs.find((r) => r.run_id === activeRunId) ?? runs[0],
    [runs, activeRunId],
  );

  const radarData = useMemo(() => {
    if (!activeRun) return [];
    const metrics = ["precision", "recall", "f1_score"] as const;
    return metrics.map((m) => {
      const row: Record<string, number | string> = { metric: m.replace("_", " ") };
      activeRun.models.forEach((mod) => {
        row[mod.model_name] = Number((mod[m] * 100).toFixed(1));
      });
      return row;
    });
  }, [activeRun]);

  const latencyData = useMemo(() => {
    if (!activeRun) return [];
    return activeRun.models.map((m) => ({
      name: m.model_name.split("-")[0],
      latency: m.avg_latency_ms,
      tokens: m.total_tokens,
    }));
  }, [activeRun]);

  return (
    <>
      <TopBar
        title="Model Benchmarks"
        subtitle="Foundation-Sec-8B-Reasoning vs Qwen2.5-7B"
        actions={
          isMock && (
            <span className="rounded border border-warning/40 bg-warning/10 px-2 py-0.5 font-mono text-[10px] text-warning">
              MOCK
            </span>
          )
        }
      />
      <PageContainer>
        {loading ? (
          <div className="glass rounded-lg p-12 text-center text-xs text-muted-foreground">
            Loading benchmark runs…
          </div>
        ) : runs.length === 0 || !activeRun ? (
          <EmptyState
            icon={GitCompare}
            title="No benchmark runs yet"
            description="Trigger a benchmark from a completed scan to compare model precision, recall, and latency."
          />
        ) : (
          <>
            {/* Run selector */}
            <div className="mb-4 flex flex-wrap gap-2">
              {runs.map((r) => (
                <button
                  key={r.run_id}
                  type="button"
                  onClick={() => setActiveRunId(r.run_id)}
                  className={cn(
                    "rounded-md border px-3 py-1.5 font-mono text-[11px] transition-colors",
                    r.run_id === activeRun.run_id
                      ? "border-primary bg-primary/10 text-primary"
                      : "border-border text-muted-foreground hover:bg-surface-hover hover:text-foreground",
                  )}
                >
                  <span className="uppercase tracking-widest">{r.target_api}</span>
                  <span className="ml-2 text-[10px] text-muted-foreground">
                    {new Date(r.timestamp).toLocaleDateString()}
                  </span>
                </button>
              ))}
            </div>

            {/* Metric cards */}
            <div className="mb-4 grid gap-3 md:grid-cols-2">
              {activeRun.models.map((m) => (
                <div key={m.model_name} className="glass rounded-lg p-4">
                  <div className="mb-3 flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span
                        className="h-2.5 w-2.5 rounded-full"
                        style={{ backgroundColor: MODEL_COLORS[m.model_name] ?? "var(--cyan)" }}
                      />
                      <span className="font-mono text-xs text-foreground">{m.model_name}</span>
                    </div>
                    <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                      F1 {(m.f1_score * 100).toFixed(1)}%
                    </span>
                  </div>
                  <div className="grid grid-cols-4 gap-2 text-center font-mono text-[11px]">
                    <Stat label="Precision" value={`${(m.precision * 100).toFixed(0)}%`} accent="cyan" />
                    <Stat label="Recall" value={`${(m.recall * 100).toFixed(0)}%`} accent="cyan" />
                    <Stat label="TP" value={String(m.true_positives)} accent="success" />
                    <Stat label="FP" value={String(m.false_positives)} accent="warning" />
                  </div>
                  <div className="mt-3 grid grid-cols-3 gap-2 border-t border-border pt-3 text-center font-mono text-[11px]">
                    <Stat label="Latency" value={`${m.avg_latency_ms}ms`} />
                    <Stat label="Tokens" value={`${(m.total_tokens / 1000).toFixed(0)}k`} />
                    <Stat label="Fallbacks" value={String(m.fallback_count)} />
                  </div>
                </div>
              ))}
            </div>

            {/* Charts */}
            <div className="grid gap-4 lg:grid-cols-2">
              <ChartCard title="Precision · Recall · F1">
                <ResponsiveContainer width="100%" height={260}>
                  <RadarChart data={radarData}>
                    <PolarGrid stroke="var(--border)" />
                    <PolarAngleAxis
                      dataKey="metric"
                      tick={{ fill: "var(--muted-foreground)", fontSize: 10, fontFamily: "var(--font-mono)" }}
                    />
                    <PolarRadiusAxis
                      angle={90}
                      domain={[0, 100]}
                      tick={{ fill: "var(--muted-foreground)", fontSize: 9 }}
                    />
                    {activeRun.models.map((m) => (
                      <Radar
                        key={m.model_name}
                        name={m.model_name}
                        dataKey={m.model_name}
                        stroke={MODEL_COLORS[m.model_name] ?? "var(--cyan)"}
                        fill={MODEL_COLORS[m.model_name] ?? "var(--cyan)"}
                        fillOpacity={0.2}
                      />
                    ))}
                    <Tooltip
                      contentStyle={{
                        background: "var(--card)",
                        border: "1px solid var(--border)",
                        borderRadius: 6,
                        fontSize: 11,
                        fontFamily: "var(--font-mono)",
                      }}
                    />
                    <Legend
                      wrapperStyle={{ fontSize: 10, fontFamily: "var(--font-mono)" }}
                    />
                  </RadarChart>
                </ResponsiveContainer>
              </ChartCard>

              <ChartCard title="Avg Latency (ms)" icon={<Zap className="h-3 w-3" />}>
                <ResponsiveContainer width="100%" height={260}>
                  <BarChart data={latencyData} margin={{ top: 8, right: 12, left: -12, bottom: 0 }}>
                    <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" vertical={false} />
                    <XAxis
                      dataKey="name"
                      stroke="var(--muted-foreground)"
                      tick={{ fontSize: 10, fontFamily: "var(--font-mono)" }}
                    />
                    <YAxis
                      stroke="var(--muted-foreground)"
                      tick={{ fontSize: 10, fontFamily: "var(--font-mono)" }}
                    />
                    <Tooltip
                      cursor={{ fill: "color-mix(in oklab, var(--cyan) 8%, transparent)" }}
                      contentStyle={{
                        background: "var(--card)",
                        border: "1px solid var(--border)",
                        borderRadius: 6,
                        fontSize: 11,
                        fontFamily: "var(--font-mono)",
                      }}
                    />
                    <Bar dataKey="latency" radius={[4, 4, 0, 0]}>
                      {latencyData.map((_, i) => (
                        <Cell
                          key={i}
                          fill={
                            activeRun.models[i]
                              ? MODEL_COLORS[activeRun.models[i].model_name] ?? "var(--cyan)"
                              : "var(--cyan)"
                          }
                        />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </ChartCard>
            </div>
          </>
        )}
      </PageContainer>
    </>
  );
}

function Stat({
  label,
  value,
  accent,
}: {
  label: string;
  value: string;
  accent?: "cyan" | "success" | "warning";
}) {
  const color =
    accent === "cyan"
      ? "text-cyan"
      : accent === "success"
        ? "text-success"
        : accent === "warning"
          ? "text-warning"
          : "text-foreground";
  return (
    <div>
      <div className="text-[9px] uppercase tracking-widest text-muted-foreground">{label}</div>
      <div className={cn("tabular-nums", color)}>{value}</div>
    </div>
  );
}

function ChartCard({
  title,
  icon,
  children,
}: {
  title: string;
  icon?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <div className="glass rounded-lg p-4">
      <div className="mb-2 flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
        {icon}
        {title}
      </div>
      {children}
    </div>
  );
}
