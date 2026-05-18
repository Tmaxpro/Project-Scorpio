import { useState } from "react";
import { EvidenceDrawer } from "@/components/scan/EvidenceDrawer";
import { FindingsList, SeverityCounters } from "@/components/scan/FindingsPanel";
import { LiveLog } from "@/components/scan/LiveLog";
import { RadarView } from "@/components/scan/RadarView";
import { Progress } from "@/components/ui/progress";
import { useScanStream } from "@/lib/useScanStream";
import type { TaskResult } from "@/lib/types";
import { cn } from "@/lib/utils";

interface ScanDashboardProps {
  scanId: string;
}

export function ScanDashboard({ scanId }: ScanDashboardProps) {
  const state = useScanStream(scanId);
  const [selected, setSelected] = useState<TaskResult | null>(null);

  const statusColor = {
    connecting: "text-muted-foreground",
    running: "text-cyan",
    completed: "text-success",
    failed: "text-[var(--sev-critical)]",
  }[state.status];

  return (
    <div className="flex h-full flex-col">
      {/* Status + progress */}
      <div className="glass relative mb-4 shrink-0 overflow-hidden rounded-lg p-4">
        <div className="mb-2 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
              Progress
            </span>
            <span className={cn("font-mono text-[10px] uppercase tracking-widest", statusColor)}>
              {state.status}
            </span>
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
        {/* Fixed-height row so appearing endpoints don't shift the layout */}
        <div className="mt-3 flex min-h-[22px] flex-wrap gap-1.5">
          {state.activeEndpoints.map((e) => (
            <span
              key={e}
              className="rounded border border-cyan/30 bg-cyan/10 px-2 py-0.5 font-mono text-[10px] text-cyan"
            >
              ▶ {e}
            </span>
          ))}
        </div>
      </div>

      {/* Severity strip */}
      <div className="mb-4 shrink-0">
        <SeverityCounters bySeverity={state.bySeverity} />
      </div>

      {/* Main layout */}
      <div className="flex min-h-0 flex-1 flex-col gap-4">
        <div className="grid shrink-0 grid-cols-1 gap-4 lg:grid-cols-3">
          <div className="lg:col-span-1">
            <RadarView findings={state.findings} progress={state.progress} />
          </div>
          <div className="lg:col-span-2 lg:relative">
            <div className="h-[400px] lg:absolute lg:inset-0 lg:h-auto">
              <FindingsList findings={state.findings} onSelect={setSelected} />
            </div>
          </div>
        </div>
        <div className="min-h-0 flex-1">
          <LiveLog logs={state.logs} />
        </div>
      </div>

      <EvidenceDrawer finding={selected} onClose={() => setSelected(null)} />
    </div>
  );
}
