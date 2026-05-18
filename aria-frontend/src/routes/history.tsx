import { useEffect, useState } from "react";
import { createFileRoute, Link } from "@tanstack/react-router";
import { ChevronRight, Inbox, Plus, Search } from "lucide-react";
import { EmptyState } from "@/components/ui/empty-state";
import { PageContainer } from "@/components/layout/PageContainer";
import { TopBar } from "@/components/layout/TopBar";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { getAllScans } from "@/lib/api";
import type { ScanResult, ScanStatus } from "@/lib/types";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/history")({
  component: HistoryPage,
});

const STATUS_FILTERS: { value: "all" | ScanStatus; label: string }[] = [
  { value: "all", label: "All" },
  { value: "running", label: "Running" },
  { value: "completed", label: "Completed" },
  { value: "failed", label: "Failed" },
  { value: "queued", label: "Queued" },
];

const STATUS_CHIP: Record<ScanStatus, string> = {
  pending: "border-border bg-muted text-muted-foreground",
  running: "border-cyan/40 bg-cyan/10 text-cyan",
  completed: "border-success/40 bg-success/10 text-success",
  failed: "border-[var(--sev-critical)]/40 bg-[var(--sev-critical)]/10 text-[var(--sev-critical)]",
  queued: "border-border bg-muted text-muted-foreground",
};

function HistoryPage() {
  const [scans, setScans] = useState<ScanResult[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<"all" | ScanStatus>("all");
  const [query, setQuery] = useState("");

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const data = await getAllScans();
        if (!cancelled) setScans(data);
      } catch {
        /* backend unreachable — leave scans empty */
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const filtered = scans.filter((s) => {
    if (filter !== "all" && s.status !== filter) return false;
    if (
      query &&
      !(s.target ?? "").toLowerCase().includes(query.toLowerCase()) &&
      !(s.scan_name ?? "").toLowerCase().includes(query.toLowerCase()) &&
      !s.scan_id.includes(query)
    )
      return false;
    return true;
  });

  return (
    <>
      <TopBar
        title="Scan History"
        subtitle={`${scans.length} total scans`}
      />
      <PageContainer className="flex h-[calc(100vh-56px)] flex-col pb-6">
        <div className="mb-4 flex shrink-0 flex-wrap items-center gap-3">
          <div className="relative min-w-[240px] flex-1">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search target or scan id…"
              className="pl-9 font-mono text-xs"
            />
          </div>
          <div className="flex gap-1">
            {STATUS_FILTERS.map((f) => (
              <button
                key={f.value}
                type="button"
                onClick={() => setFilter(f.value)}
                className={cn(
                  "ui-chip ui-chip-sm transition-colors",
                  filter === f.value
                    ? "border-primary bg-primary/10 text-primary"
                    : "border-border text-muted-foreground hover:bg-surface-hover hover:text-foreground",
                )}
              >
                {f.label}
              </button>
            ))}
          </div>
        </div>

        <div className="glass flex min-h-0 flex-1 flex-col overflow-hidden rounded-lg">
          {loading ? (
            <div className="p-12 text-center text-xs text-muted-foreground">Loading…</div>
          ) : filtered.length === 0 ? (
            <EmptyState
              icon={Inbox}
              title={scans.length === 0 ? "No scans yet" : "No matches"}
              description={
                scans.length === 0
                  ? "Launch your first ARIA scan to see it appear here."
                  : "Try a different status filter or clear the search query."
              }
              action={
                scans.length === 0 ? (
                  <Button asChild size="sm">
                    <Link to="/scan/new">
                      <Plus className="mr-1.5 h-3.5 w-3.5" />
                      New Scan
                    </Link>
                  </Button>
                ) : null
              }
              className="border-0"
            />
          ) : (
            <div className="flex-1 overflow-auto">
              <table className="w-full text-left text-xs relative">
                <thead className="sticky top-0 z-10 border-b border-border bg-background/80 backdrop-blur-md">
                  <tr className="ui-label">
                    <th className="px-4 py-2.5">Status</th>
                    <th className="px-4 py-2.5">Target</th>
                    <th className="px-4 py-2.5">Scan ID</th>
                    <th className="px-4 py-2.5 text-right">Findings</th>
                    <th className="px-4 py-2.5 text-right">Tasks</th>
                    <th className="px-4 py-2.5">Started</th>
                    <th className="px-4 py-2.5"></th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {filtered.map((s) => (
                    <tr key={s.scan_id} className="group hover:bg-surface-hover/40">
                      <td className="px-4 py-3">
                        <span
                          className={cn(
                            "ui-chip ui-chip-sm",
                            STATUS_CHIP[s.status],
                          )}
                        >
                          {s.status}
                        </span>
                      </td>
                      <td className="px-4 py-3 font-mono text-foreground">{s.target}</td>
                      <td className="px-4 py-3 font-mono text-[11px] text-muted-foreground">
                        {s.scan_id}
                      </td>
                      <td className="px-4 py-3 text-right font-mono tabular-nums">
                        <span className={(s.findings_count ?? 0) > 0 ? "text-warning" : "text-muted-foreground"}>
                          {s.findings_count ?? 0}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-right font-mono tabular-nums text-muted-foreground">
                        {s.completed_tasks ?? 0}/{s.total_tasks ?? 0}
                      </td>
                      <td className="px-4 py-3 font-mono text-[11px] text-muted-foreground">
                        {s.started_at ? new Date(s.started_at).toLocaleString() : "—"}
                      </td>
                      <td className="px-4 py-3 text-right">
                        <Button asChild size="sm" variant="ghost" className="opacity-60 group-hover:opacity-100">
                          <Link to="/scan/$id" params={{ id: s.scan_id }}>
                            Open <ChevronRight className="ml-1 h-3 w-3" />
                          </Link>
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </PageContainer>
    </>
  );
}
