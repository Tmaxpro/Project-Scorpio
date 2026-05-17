import { useState } from "react";
import { createFileRoute, Link } from "@tanstack/react-router";
import { Activity, Pause, Square } from "lucide-react";
import { PageContainer } from "@/components/layout/PageContainer";
import { TopBar } from "@/components/layout/TopBar";
import { EvidenceDrawer } from "@/components/scan/EvidenceDrawer";
import { FindingsList, SeverityCounters } from "@/components/scan/FindingsPanel";
import { LiveLog } from "@/components/scan/LiveLog";
import { RadarView } from "@/components/scan/RadarView";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { useScanStream } from "@/lib/useScanStream";
import type { TaskResult } from "@/lib/types";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/scan/$id")({
  component: ScanDashboardPage,
});

function ScanDashboardPage() {
  const { id } = Route.useParams();
  const state = useScanStream(id);
  const [selected, setSelected] = useState<TaskResult | null>(null);

  const statusColor = {
    connecting: "text-muted-foreground",
    running: "text-cyan",
    completed: "text-success",
    failed: "text-[var(--sev-critical)]",
  }[state.status];

  return (
    <>
      <TopBar
        title={`Scan ${id}`}
        subtitle={state.scan.target}
        actions={
          <>
            <span
              className={cn(
                "flex items-center gap-1.5 font-mono text-xs uppercase tracking-widest",
                statusColor,
              )}
            >
              <Activity className="h-3.5 w-3.5 animate-pulse-dot" />
              {state.status}
              {state.source === "mock" && (
                <span className="ml-2 rounded border border-warning/40 bg-warning/10 px-1.5 py-0.5 text-[10px] text-warning">
                  MOCK
                </span>
              )}
            </span>
            <Button variant="outline" size="sm" disabled>
              <Pause className="mr-1.5 h-3.5 w-3.5" />
              Pause
            </Button>
            <Button variant="outline" size="sm" disabled>
              <Square className="mr-1.5 h-3.5 w-3.5" />
              Stop
            </Button>
            <Button asChild size="sm" variant="ghost">
              <Link to="/history">History</Link>
            </Button>
          </>
        }
      />
      <PageContainer>
        {/* Progress bar */}
        <div className="glass relative mb-4 overflow-hidden rounded-lg p-4">
          <div className="mb-2 flex items-center justify-between">
            <div className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
              Progress
            </div>
            <div className="font-mono text-xs text-foreground">
              {state.completedTasks} / {state.totalTasks} tasks
              <span className="ml-3 text-cyan">{state.progress.toFixed(1)}%</span>
            </div>
          </div>
          <Progress value={state.progress} className="h-1.5 bg-surface" />
          {state.status === "running" && (
            <div className="pointer-events-none absolute inset-x-0 bottom-0 h-1.5 overflow-hidden">
              <div className="h-full w-1/4 animate-scan-beam bg-gradient-to-r from-transparent via-cyan to-transparent opacity-60" />
            </div>
          )}
          {state.activeEndpoints.length > 0 && (
            <div className="mt-3 flex flex-wrap gap-1.5">
              {state.activeEndpoints.map((e) => (
                <span
                  key={e}
                  className="rounded border border-cyan/30 bg-cyan/10 px-2 py-0.5 font-mono text-[10px] text-cyan"
                >
                  ▶ {e}
                </span>
              ))}
            </div>
          )}
        </div>

        {/* Severity strip */}
        <div className="mb-4">
          <SeverityCounters bySeverity={state.bySeverity} />
        </div>

        {/* Main grid */}
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
          <div className="lg:col-span-1">
            <RadarView findings={state.findings} progress={state.progress} />
          </div>
          <div className="lg:col-span-2 grid grid-rows-2 gap-4" style={{ minHeight: 600 }}>
            <FindingsList findings={state.findings} onSelect={setSelected} />
            <LiveLog logs={state.logs} />
          </div>
        </div>
      </PageContainer>
      <EvidenceDrawer finding={selected} onClose={() => setSelected(null)} />
    </>
  );
}
