import { useEffect, useRef } from "react";
import { ScrollArea } from "@/components/ui/scroll-area";
import type { LogEntry } from "@/lib/useScanStream";
import { cn } from "@/lib/utils";

const LEVEL_COLOR: Record<LogEntry["level"], string> = {
  info: "text-cyan",
  warn: "text-[var(--warning)]",
  error: "text-[var(--sev-critical)]",
  finding: "text-[var(--sev-high)]",
};

interface LiveLogProps {
  logs: LogEntry[];
}

export function LiveLog({ logs }: LiveLogProps) {
  return (
    <div className="glass scanlines flex h-full flex-col overflow-hidden rounded-lg">
      <div className="flex items-center justify-between border-b border-border px-3 py-2">
        <div className="flex items-center gap-2">
          <span className="h-2 w-2 animate-pulse-dot rounded-full bg-success text-success" />
          <h3 className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
            Live Stream
          </h3>
        </div>
        <span className="font-mono text-[10px] text-muted-foreground">
          {logs.length} events
        </span>
      </div>
      <ScrollArea className="flex-1">
        <div className="space-y-0.5 p-3 font-mono text-xs">
          {logs.length === 0 && (
            <div className="text-muted-foreground">Awaiting events…</div>
          )}
          {[...logs].sort((a, b) => b.ts.localeCompare(a.ts)).map((l) => (
            <div key={l.id} className="flex gap-2 hover:bg-surface-hover/40 px-1 -mx-1 rounded">
              <span className="shrink-0 text-muted-foreground/60">
                {new Date(l.ts).toTimeString().slice(0, 8)}
              </span>
              <span className={cn("shrink-0 uppercase", LEVEL_COLOR[l.level])}>
                {l.level}
              </span>
              <span className="text-foreground/90">{l.message}</span>
            </div>
          ))}
        </div>
      </ScrollArea>
    </div>
  );
}
