import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { ModelBenchmarkResult, ModelName, OWASPCategory } from "@/lib/types";

interface Props {
  results: ModelBenchmarkResult[];
}

const OWASP_CATS: OWASPCategory[] = [
  "API1", "API2", "API3", "API4", "API5",
  "API6", "API7", "API8", "API9", "API10",
];

const MODEL_COLORS: Record<ModelName, string> = {
  "foundation-sec-reasoning": "var(--cyan)",
  "foundation-sec-instruct": "var(--cyan)",
  "qwen2.5": "var(--violet)",
  both: "var(--cyan)",
};

const MODEL_LABELS: Record<ModelName, string> = {
  "foundation-sec-reasoning": "F-Sec TP",
  "foundation-sec-instruct": "F-Sec TP",
  "qwen2.5": "Qwen TP",
  both: "Both TP",
};

/**
 * Grouped bar chart: per OWASP category, shows ground truth count (gray) and
 * per-model true positives (colored) + aggregate false positives (red thin).
 */
export function CategoryCoverageChart({ results }: Props) {
  const data = OWASP_CATS.map((cat) => {
    const gt = results[0]?.by_owasp_category[cat]?.ground_truth_count ?? 0;
    const row: Record<string, number | string> = { category: cat, "Ground truth": gt };
    let fpTotal = 0;
    for (const r of results) {
      row[MODEL_LABELS[r.model]] = r.by_owasp_category[cat]?.found_count ?? 0;
      fpTotal += r.by_owasp_category[cat]?.fp_count ?? 0;
    }
    row["FP"] = fpTotal;
    return row;
  });

  return (
    <ResponsiveContainer width="100%" height={300}>
      <BarChart data={data} margin={{ top: 8, right: 12, left: -12, bottom: 0 }}>
        <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" vertical={false} />
        <XAxis
          dataKey="category"
          stroke="var(--muted-foreground)"
          tick={{ fontSize: 10, fontFamily: "var(--font-mono)" }}
        />
        <YAxis
          stroke="var(--muted-foreground)"
          tick={{ fontSize: 10, fontFamily: "var(--font-mono)" }}
          allowDecimals={false}
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
        <Legend wrapperStyle={{ fontSize: 10, fontFamily: "var(--font-mono)" }} />
        <Bar dataKey="Ground truth" fill="var(--muted-foreground)" radius={[3, 3, 0, 0]} />
        {results.map((r) => (
          <Bar
            key={r.model}
            dataKey={MODEL_LABELS[r.model]}
            fill={MODEL_COLORS[r.model]}
            radius={[3, 3, 0, 0]}
          />
        ))}
        <Bar dataKey="FP" fill="var(--destructive, #f85149)" radius={[3, 3, 0, 0]} />
      </BarChart>
    </ResponsiveContainer>
  );
}
