import { useEffect, useState } from "react";
import { Link, useRouterState } from "@tanstack/react-router";
import {
  BarChart2,
  ChevronLeft,
  ChevronRight,
  Clock,
  FileText,
  Zap,
} from "lucide-react";
import { checkHealth } from "@/lib/api";
import { cn } from "@/lib/utils";

const NAV = [
  { to: "/scan/new", label: "New Scan", icon: Zap },
  { to: "/history", label: "History", icon: Clock },
  { to: "/reports", label: "Reports", icon: FileText },
  { to: "/benchmarks", label: "Benchmarks", icon: BarChart2 },
] as const;

export function Sidebar() {
  const [collapsed, setCollapsed] = useState(false);
  const [online, setOnline] = useState<boolean>(false);
  const pathname = useRouterState({ select: (s) => s.location.pathname });

  useEffect(() => {
    let mounted = true;
    const ping = async () => {
      const ok = await checkHealth();
      if (mounted) setOnline(ok);
    };
    ping();
    const id = setInterval(ping, 10_000);
    return () => {
      mounted = false;
      clearInterval(id);
    };
  }, []);

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
              <div className="flex items-center gap-1.5">
                <span className="h-1.5 w-1.5 rounded-full bg-cyan" />
                Foundation-Sec-8B
              </div>
              <div className="flex items-center gap-1.5">
                <span className="h-1.5 w-1.5 rounded-full bg-violet" />
                Qwen2.5-7B
              </div>
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
