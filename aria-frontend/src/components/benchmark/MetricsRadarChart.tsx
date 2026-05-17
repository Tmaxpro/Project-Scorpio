import {
  Legend,
  PolarAngleAxis,
  PolarGrid,
  PolarRadiusAxis,
  Radar,
  RadarChart,
  ResponsiveContainer,
  Tooltip,
} from "recharts";
import type { ModelBenchmarkResult, ModelName } from "@/lib/types";

interface Props {
  results: ModelBenchmarkResult[];
}

const MODEL_COLORS: Record<ModelName, string> = {
  "foundation-sec-reasoning": "var(--cyan)",
  "foundation-sec-instruct": "var(--cyan)",
  "qwen2.5": "var(--violet)",
  both: "var(--cyan)",
};

const MODEL_LABELS: Record<ModelName, string> = {
  "foundation-sec-reasoning": "Foundation-Sec",
  "foundation-sec-instruct": "Foundation-Sec",
  "qwen2.5": "Qwen2.5",
  both: "Both",
};

/**
 * Radar chart with 5 axes: Precision · Recall · F1 · Speed · Reliability.
 * Each model is one polygon. Values are normalized 0-100%.
 */
export function MetricsRadarChart({ results }: Props) {
  if (results.length === 0) return null;

  const maxLatency = Math.max(1, ...results.map((r) => r.avg_latency_ms));

  const metrics = ["Precision", "Recall", "F1", "Speed", "Reliability"] as const;
  const data = metrics.map((metric) => {
    const row: Record<string, number | string> = { metric };
    for (const r of results) {
      let v = 0;
      switch (metric) {
        case "Precision":
          v = r.precision;
          break;
        case "Recall":
          v = r.recall;
          break;
        case "F1":
          v = r.f1_score;
          break;
        case "Speed":
          v = 1 - r.avg_latency_ms / maxLatency;
          break;
        case "Reliability": {
          const totalTasks = r.true_positives + r.false_positives + r.false_negatives;
          v = totalTasks > 0 ? 1 - r.fallback_count / totalTasks : 1;
          break;
        }
      }
      row[MODEL_LABELS[r.model]] = Number((v * 100).toFixed(1));
    }
    return row;
  });

  return (
    <ResponsiveContainer width="100%" height={300}>
      <RadarChart data={data}>
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
        {results.map((r) => (
          <Radar
            key={r.model}
            name={MODEL_LABELS[r.model]}
            dataKey={MODEL_LABELS[r.model]}
            stroke={MODEL_COLORS[r.model]}
            fill={MODEL_COLORS[r.model]}
            fillOpacity={0.25}
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
          formatter={(v: number) => `${v.toFixed(1)}%`}
        />
        <Legend wrapperStyle={{ fontSize: 10, fontFamily: "var(--font-mono)" }} />
      </RadarChart>
    </ResponsiveContainer>
  );
}
