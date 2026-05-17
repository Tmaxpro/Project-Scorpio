import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { Info, History } from "lucide-react";
import { PageContainer } from "@/components/layout/PageContainer";
import { TopBar } from "@/components/layout/TopBar";
import { TargetCard } from "@/components/benchmark/TargetCard";
import { BenchmarkLaunchForm } from "@/components/benchmark/BenchmarkLaunchForm";
import { BenchmarkRunCard } from "@/components/benchmark/BenchmarkRunCard";
import { TARGET_APIS } from "@/lib/benchmark-ground-truth";
import { useBenchmarkList } from "@/hooks/useBenchmark";
import type { BenchmarkTarget } from "@/lib/types";

export const Route = createFileRoute("/benchmarks")({
  component: BenchmarksPage,
});

const TARGETS: BenchmarkTarget[] = ["vampi", "dvapi", "crapi"];

function BenchmarksPage() {
  const [selected, setSelected] = useState<BenchmarkTarget | null>(null);
  const { runs } = useBenchmarkList();
  const [historyOpen, setHistoryOpen] = useState(true);

  return (
    <>
      <TopBar
        title="Benchmark Arena"
        subtitle="Measure ARIA performance against known vulnerable APIs using grey-box methodology"
      />
      <PageContainer className="max-w-6xl">
        {/* Grey-box info banner */}
        <div className="mb-6 flex items-start gap-3 rounded-md border border-warning/40 bg-warning/10 p-3">
          <Info className="mt-0.5 h-4 w-4 shrink-0 text-warning" />
          <div className="font-mono text-[11px] text-warning">
            <strong>Grey-box mode</strong> — You must provide the OpenAPI spec and user
            credentials for each target. This mirrors real pentest conditions.
          </div>
        </div>

        {/* Section 1 — Target cards */}
        <section className="mb-8">
          <SectionTitle step="Step 1" title="Choose a target" />
          <div className="grid gap-4 md:grid-cols-3">
            {TARGETS.map((t) => (
              <TargetCard
                key={t}
                config={TARGET_APIS[t]}
                selected={selected === t}
                onSelect={() => setSelected(t)}
              />
            ))}
          </div>
        </section>

        {/* Section 2 — Launch form */}
        {selected && (
          <section className="mb-8">
            <BenchmarkLaunchForm key={selected} target={selected} />
          </section>
        )}

        {!selected && runs.length === 0 && (
          <div className="mb-8 rounded-md border border-dashed border-border bg-card/30 p-8 text-center font-mono text-[11px] uppercase tracking-widest text-muted-foreground">
            Select a target above to configure a benchmark run.
          </div>
        )}

        {/* Section 3 — History */}
        {runs.length > 0 && (
          <section>
            <div className="mb-3 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <History className="h-4 w-4 text-primary" />
                <SectionTitle step="History" title={`Past runs (${runs.length})`} inline />
              </div>
              <button
                type="button"
                onClick={() => setHistoryOpen((v) => !v)}
                className="rounded-md border border-border bg-card px-3 py-1 font-mono text-[10px] uppercase tracking-widest text-muted-foreground hover:bg-surface-hover hover:text-foreground"
              >
                {historyOpen ? "Hide" : "Show"}
              </button>
            </div>
            {historyOpen && (
              <div className="space-y-2">
                {runs.map((r) => (
                  <BenchmarkRunCard
                    key={r.run_id}
                    run={r}
                    onDeleted={() => {/* useBenchmarkList polls localStorage */}}
                  />
                ))}
              </div>
            )}
          </section>
        )}
      </PageContainer>
    </>
  );
}

function SectionTitle({
  step,
  title,
  inline = false,
}: {
  step: string;
  title: string;
  inline?: boolean;
}) {
  if (inline) {
    return (
      <div>
        <div className="font-mono text-[10px] uppercase tracking-widest text-primary">
          {step}
        </div>
        <h2 className="text-lg font-semibold text-foreground">{title}</h2>
      </div>
    );
  }
  return (
    <div className="mb-3">
      <div className="font-mono text-[10px] uppercase tracking-widest text-primary">
        {step}
      </div>
      <h2 className="text-lg font-semibold text-foreground">{title}</h2>
    </div>
  );
}
