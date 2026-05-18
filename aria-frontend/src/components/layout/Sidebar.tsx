import { useEffect, useState } from "react";
import { Link, useRouterState } from "@tanstack/react-router";
import {
  BarChart2,
  ChevronLeft,
  ChevronRight,
  Clock,
  FileText,
  Settings,
  Zap,
} from "lucide-react";
import { checkHealth, getModelsConfig, listBenchmarkRuns } from "@/lib/api";
import type { ModelsResponse } from "@/lib/types";
import { MODEL_ROLE_META } from "@/lib/types";
import { cn } from "@/lib/utils";

const NAV = [
  { to: "/scan/new", label: "New Scan", icon: Zap },
  { to: "/history", label: "History", icon: Clock },
  { to: "/reports", label: "Reports", icon: FileText },
  { to: "/benchmarks", label: "Benchmarks", icon: BarChart2 },
  { to: "/settings", label: "Settings", icon: Settings },
] as const;

export function Sidebar() {
  const [collapsed, setCollapsed] = useState(false);
  const [online, setOnline] = useState<boolean>(false);
  const [benchmarkCount, setBenchmarkCount] = useState<number>(0);
  const [modelsConfig, setModelsConfig] = useState<ModelsResponse | null>(null);
  const pathname = useRouterState({ select: (s) => s.location.pathname });

  useEffect(() => {
    let mounted = true;
    const ping = async () => {
      const ok = await checkHealth();
      if (mounted) setOnline(ok);
    };
    const refreshBenchmarks = async () => {
      if (!mounted) return;
      try {
        const runs = await listBenchmarkRuns();
        if (mounted) setBenchmarkCount(runs.filter((r) => r.status === "completed").length);
      } catch {
        // Backend may be offline
      }
    };
    const refreshModels = async () => {
      if (!mounted) return;
      try {
        const cfg = await getModelsConfig();
        if (mounted) setModelsConfig(cfg);
      } catch {
        // Backend may be offline — silently ignore
      }
    };
    ping();
    refreshBenchmarks();
    refreshModels();
    const id = setInterval(ping, 10_000);
    const benchId = setInterval(refreshBenchmarks, 3_000);
    const modelsId = setInterval(refreshModels, 15_000);
    window.addEventListener("aria:models-updated", refreshModels);
    return () => {
      mounted = false;
      clearInterval(id);
      clearInterval(benchId);
      clearInterval(modelsId);
      window.removeEventListener("aria:models-updated", refreshModels);
    };
  }, []);

  // Extract short display names from model names
  const getShortName = (name: string) => {
    if (name.includes("/")) {
      const last = name.split("/").pop() || name;
      return last.replace(/-GGUF$/, "").replace(/[-_]Q\d.*$/, "").slice(0, 22);
    }
    return name.slice(0, 22);
  };

  const ROLE_ORDER = ["reasoning_model", "instruct_model", "fallback_model"] as const;
  const dotColors: Record<string, string> = {
    cyan: "bg-cyan",
    violet: "bg-violet",
    warning: "bg-warning",
  };

  return (
    <aside
      className={cn(
        "sticky top-0 flex h-screen flex-col border-r border-border bg-sidebar transition-[width] duration-200",
        collapsed ? "w-16" : "w-60",
      )}
    >
      {/* Brand */}
      <div className="flex items-center gap-3 border-b border-border px-4 py-4">
        <div className="relative flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-primary/10 text-primary glow-cyan">
          <span className="font-mono text-sm font-bold">A</span>
        </div>
        {!collapsed && (
          <div className="min-w-0 flex-1">
            <div className="font-mono text-base font-bold tracking-tight text-primary">
              ARIA
            </div>
            <div className="truncate text-[10px] uppercase tracking-widest text-muted-foreground">
              API Security Agent
            </div>
          </div>
        )}
        {!collapsed && (
          <span
            aria-label={online ? "Backend online" : "Backend offline"}
            className={cn(
              "h-2 w-2 rounded-full",
              online
                ? "bg-success animate-pulse-dot text-success"
                : "bg-danger text-danger",
            )}
          />
        )}
      </div>

      {/* Nav */}
      <nav className="flex-1 px-2 py-4">
        <ul className="space-y-1">
          {NAV.map(({ to, label, icon: Icon }) => {
            const active = pathname === to || pathname.startsWith(to + "/");
            const showBadge = to === "/benchmarks" && benchmarkCount > 0;
            return (
              <li key={to}>
                <Link
                  to={to}
                  aria-label={label}
                  className={cn(
                    "group relative flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors",
                    active
                      ? "bg-primary/10 text-primary"
                      : "text-muted-foreground hover:bg-surface-hover hover:text-foreground",
                  )}
                >
                  {active && (
                    <span className="absolute left-0 top-1 bottom-1 w-0.5 rounded-r bg-primary glow-cyan" />
                  )}
                  <Icon className="h-4 w-4 shrink-0" strokeWidth={1.75} />
                  {!collapsed && (
                    <span className="truncate text-xs uppercase tracking-wider">
                      {label}
                    </span>
                  )}
                  {showBadge && !collapsed && (
                    <span className="ml-auto rounded-full bg-card px-2 py-0.5 font-mono text-[9px] tabular-nums text-muted-foreground">
                      {benchmarkCount}
                    </span>
                  )}
                  {showBadge && collapsed && (
                    <span className="absolute right-1 top-1 h-1.5 w-1.5 rounded-full bg-primary" />
                  )}
                </Link>
              </li>
            );
          })}
        </ul>
      </nav>

      {/* Footer */}
      <div className="border-t border-border px-3 py-3">
        {!collapsed && (
          <div className="mb-3 space-y-1">
            <div className="text-[9px] uppercase tracking-widest text-muted-foreground">
              Active Models
            </div>
            <div className="space-y-0.5 font-mono text-[10px] text-foreground/80">
              {modelsConfig ? (
                ROLE_ORDER.map((role) => {
                  const model = modelsConfig.models[role];
                  if (!model) return null;
                  const meta = MODEL_ROLE_META[role];
                  return (
                    <div key={role} className="flex items-center gap-1.5" title={`${meta.label}: ${model.name}`}>
                      <span className={cn("h-1.5 w-1.5 shrink-0 rounded-full", dotColors[meta.color])} />
                      <span className="truncate">{getShortName(model.name)}</span>
                    </div>
                  );
                })
              ) : (
                <>
                  <div className="flex items-center gap-1.5">
                    <span className="h-1.5 w-1.5 rounded-full bg-border animate-pulse" />
                    <span className="text-muted-foreground/50">Loading...</span>
                  </div>
                </>
              )}
            </div>
          </div>
        )}
        <button
          type="button"
          onClick={() => setCollapsed((v) => !v)}
          aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          className="flex w-full items-center justify-center rounded-md border border-border py-1.5 text-muted-foreground hover:bg-surface-hover hover:text-foreground"
        >
          {collapsed ? (
            <ChevronRight className="h-3.5 w-3.5" />
          ) : (
            <ChevronLeft className="h-3.5 w-3.5" />
          )}
        </button>
      </div>
    </aside>
  );
}
