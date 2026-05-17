import { useEffect, useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { Loader2, RefreshCw, Server, Settings, Wifi, WifiOff } from "lucide-react";
import { getModelsConfig } from "@/lib/api";
import type { ModelRole, ModelsResponse } from "@/lib/types";
import { MODEL_ROLE_META } from "@/lib/types";
import { ModelCard } from "@/components/settings/ModelCard";
import { ModelEditModal } from "@/components/settings/ModelEditModal";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/settings")({
  component: SettingsPage,
});

const ROLE_ORDER: ModelRole[] = ["reasoning_model", "instruct_model", "fallback_model"];

function SettingsPage() {
  const [config, setConfig] = useState<ModelsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [editingRole, setEditingRole] = useState<ModelRole | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);

  const fetchConfig = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await getModelsConfig();
      setConfig(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load model configuration");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchConfig();
  }, [refreshKey]);

  const handleRefresh = () => setRefreshKey((k) => k + 1);

  return (
    <div className="mx-auto max-w-5xl px-6 py-8">
      {/* Page Header */}
      <div className="mb-8 flex items-start justify-between">
        <div>
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10 text-primary glow-cyan">
              <Settings className="h-5 w-5" />
            </div>
            <div>
              <h1 className="font-mono text-xl font-bold tracking-tight text-foreground">
                Model Configuration
              </h1>
              <p className="mt-0.5 text-sm text-muted-foreground">
                Manage the LLM models assigned to each pipeline role
              </p>
            </div>
          </div>
        </div>
        <button
          type="button"
          onClick={handleRefresh}
          disabled={loading}
          className="inline-flex items-center gap-2 rounded-md border border-border bg-card px-3 py-2 font-mono text-[10px] uppercase tracking-widest text-muted-foreground transition-colors hover:bg-surface-hover hover:text-foreground disabled:opacity-50"
        >
          <RefreshCw className={cn("h-3.5 w-3.5", loading && "animate-spin")} />
          Refresh
        </button>
      </div>

      {/* Provider Info Banner */}
      {config && !loading && (
        <div className="mb-6 flex flex-wrap items-center gap-4 rounded-lg border border-border bg-card/50 px-4 py-3">
          <div className="flex items-center gap-2 text-sm">
            <Server className="h-4 w-4 text-muted-foreground" />
            <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
              Provider
            </span>
            <span className="font-mono text-xs font-medium text-foreground">
              {config.provider}
            </span>
          </div>
          <div className="h-4 w-px bg-border" />
          <div className="flex items-center gap-2 text-sm">
            <Wifi className="h-4 w-4 text-muted-foreground" />
            <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
              Endpoint
            </span>
            <span className="font-mono text-xs text-foreground">
              {config.base_url}
            </span>
          </div>
          <div className="h-4 w-px bg-border" />
          <div className="flex items-center gap-2 text-sm">
            <RefreshCw className="h-3.5 w-3.5 text-muted-foreground" />
            <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
              Max Retries
            </span>
            <span className="font-mono text-xs font-medium text-foreground">
              {config.max_retries}
            </span>
          </div>
        </div>
      )}

      {/* Loading State */}
      {loading && (
        <div className="flex flex-col items-center justify-center py-24">
          <Loader2 className="h-8 w-8 animate-spin text-primary" />
          <p className="mt-4 font-mono text-xs uppercase tracking-widest text-muted-foreground">
            Loading configuration...
          </p>
        </div>
      )}

      {/* Error State */}
      {error && !loading && (
        <div className="flex flex-col items-center justify-center py-24">
          <div className="flex h-14 w-14 items-center justify-center rounded-full bg-danger/10">
            <WifiOff className="h-7 w-7 text-danger" />
          </div>
          <p className="mt-4 font-mono text-sm text-danger">{error}</p>
          <p className="mt-1 text-xs text-muted-foreground">
            Make sure the ARIA backend is running at the expected address
          </p>
          <button
            type="button"
            onClick={handleRefresh}
            className="mt-4 inline-flex items-center gap-2 rounded-md bg-primary px-4 py-2 font-mono text-[10px] uppercase tracking-widest text-primary-foreground transition-colors hover:opacity-90"
          >
            <RefreshCw className="h-3.5 w-3.5" />
            Retry
          </button>
        </div>
      )}

      {/* Model Cards Grid */}
      {config && !loading && !error && (
        <div className="grid gap-5 md:grid-cols-3">
          {ROLE_ORDER.map((role) => {
            const model = config.models[role];
            if (!model) return null;
            return (
              <ModelCard
                key={role}
                role={role}
                model={model}
                onEdit={() => setEditingRole(role)}
              />
            );
          })}
        </div>
      )}

      {/* Architecture Diagram */}
      {config && !loading && !error && (
        <div className="mt-8 rounded-lg border border-border bg-card/30 p-5">
          <div className="mb-3 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
            Pipeline Model Assignment
          </div>
          <div className="flex flex-col gap-2 font-mono text-xs">
            {ROLE_ORDER.map((role) => {
              const model = config.models[role];
              const meta = MODEL_ROLE_META[role];
              if (!model) return null;
              const dotColor: Record<string, string> = {
                cyan: "bg-cyan",
                violet: "bg-violet",
                warning: "bg-warning",
              };
              return (
                <div key={role} className="flex items-center gap-3">
                  <span className={cn("h-2 w-2 shrink-0 rounded-full", dotColor[meta.color])} />
                  <span className="w-24 text-muted-foreground">{meta.label}</span>
                  <span className="text-muted-foreground/40">→</span>
                  <span className="flex-1 text-foreground/80">
                    {model.use_for.length > 0
                      ? model.use_for.join(", ")
                      : "fallback recovery"}
                  </span>
                  <span className="text-muted-foreground/40">→</span>
                  <span className="max-w-[200px] truncate text-foreground" title={model.name}>
                    {model.name.includes("/")
                      ? model.name.split("/").pop()
                      : model.name}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Edit Modal */}
      {editingRole && config?.models[editingRole] && (
        <ModelEditModal
          role={editingRole}
          current={config.models[editingRole]}
          onClose={() => setEditingRole(null)}
          onSaved={handleRefresh}
        />
      )}
    </div>
  );
}
