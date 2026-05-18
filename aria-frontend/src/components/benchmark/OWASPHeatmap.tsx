import type { ModelBenchmarkResult, OWASPCategory } from "@/lib/types";
import { OWASP_META } from "@/lib/types";
import { cn } from "@/lib/utils";

interface Props {
  results: ModelBenchmarkResult[];
}

const OWASP_CATS: OWASPCategory[] = [
  "API1", "API2", "API3", "API4", "API5",
  "API6", "API7", "API8", "API9", "API10",
];

interface CellState {
  cat: OWASPCategory;
  gtCount: number;
  perModel: { model: string; found: number; fp: number }[];
  minFound: number;
  maxFound: number;
  totalFP: number;
}

function computeCell(cat: OWASPCategory, results: ModelBenchmarkResult[]): CellState {
  const stats = results.map((r) => ({
    model: r.model,
    found: r.by_owasp_category[cat]?.found_count ?? 0,
    fp: r.by_owasp_category[cat]?.fp_count ?? 0,
  }));
  const gtCount = results[0]?.by_owasp_category[cat]?.ground_truth_count ?? 0;
  const founds = stats.map((s) => s.found);
  return {
    cat,
    gtCount,
    perModel: stats,
    minFound: founds.length > 0 ? Math.min(...founds) : 0,
    maxFound: founds.length > 0 ? Math.max(...founds) : 0,
    totalFP: stats.reduce((s, x) => s + x.fp, 0),
  };
}

function cellTone(state: CellState): "empty" | "green" | "amber" | "red" {
  if (state.gtCount === 0) return "empty";
  if (state.minFound === state.gtCount) return "green";
  if (state.maxFound > 0) return "amber";
  return "red";
}

const TONE_STYLE = {
  empty:
    "border-border bg-[var(--panel-muted)] text-muted-foreground",
  green:
    "border-success/40 bg-success/15 text-success",
  amber:
    "border-warning/40 bg-warning/15 text-warning",
  red:
    "border-danger/40 bg-danger/15 text-danger",
} as const;

export function OWASPHeatmap({ results }: Props) {
  const cells = OWASP_CATS.map((c) => computeCell(c, results));

  return (
    <div className="grid grid-cols-2 gap-2 sm:grid-cols-5">
      {cells.map((cell) => {
        const tone = cellTone(cell);
        const meta = OWASP_META[cell.cat];
        const tooltip = cell.perModel
          .map((s) => `${prettyModel(s.model)}: ${s.found} found, ${s.fp} FP`)
          .join("\n");
        return (
          <div
            key={cell.cat}
            title={tooltip}
            className={cn(
              "relative aspect-square rounded-md border p-3 transition-colors",
              TONE_STYLE[tone],
            )}
          >
            <div className="flex h-full flex-col">
              <div className="flex items-center justify-between">
                <span className="font-mono text-xs font-bold tabular-nums">{cell.cat}</span>
                {cell.totalFP > 0 && (
                  <span className="ui-chip ui-chip-xs border-danger/40 bg-danger/20 text-danger">
                    +{cell.totalFP} FP
                  </span>
                )}
              </div>
              <div className="mt-0.5 truncate ui-label text-[8px] opacity-75">
                {meta.name}
              </div>
              <div className="mt-auto text-right">
                {tone === "empty" ? (
                  <span className="ui-label opacity-50">
                    No GT
                  </span>
                ) : (
                  <span className="font-mono text-2xl tabular-nums">
                    {cell.maxFound}
                    <span className="text-base opacity-50">/{cell.gtCount}</span>
                  </span>
                )}
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

function prettyModel(m: string): string {
  if (m === "foundation-sec-reasoning" || m === "foundation-sec-instruct") return "F-Sec";
  if (m === "qwen2.5") return "Qwen2.5";
  return m;
}
