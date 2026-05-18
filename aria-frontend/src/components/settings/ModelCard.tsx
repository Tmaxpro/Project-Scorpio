import { Cpu, Thermometer, Hash, Layers } from "lucide-react";
import type { ModelConfig, ModelRole } from "@/lib/types";
import { MODEL_ROLE_META } from "@/lib/types";
import { cn } from "@/lib/utils";

interface ModelCardProps {
  role: ModelRole;
  model: ModelConfig;
  onEdit: () => void;
}

export function ModelCard({ role, model, onEdit }: ModelCardProps) {
  const meta = MODEL_ROLE_META[role];

  const colorMap: Record<string, string> = {
    cyan: "border-cyan/30 hover:border-cyan/60",
    violet: "border-violet/30 hover:border-violet/60",
    warning: "border-warning/30 hover:border-warning/60",
  };

  const dotColorMap: Record<string, string> = {
    cyan: "bg-cyan",
    violet: "bg-violet",
    warning: "bg-warning",
  };

  const glowMap: Record<string, string> = {
    cyan: "glow-cyan",
    violet: "shadow-[0_0_14px_color-mix(in_oklab,var(--violet)_55%,transparent)]",
    warning: "shadow-[0_0_14px_color-mix(in_oklab,var(--warning)_55%,transparent)]",
  };

  const badgeBgMap: Record<string, string> = {
    cyan: "bg-cyan/15 text-cyan",
    violet: "bg-violet/15 text-violet",
    warning: "bg-warning/15 text-warning",
  };

  // Extract a short display name from the full model name
  const shortName = model.name.includes("/")
    ? model.name.split("/").pop()?.replace(/-GGUF$/, "").replace(/[-_]Q\d.*$/, "") || model.name
    : model.name;

  return (
    <div
      className={cn(
        "glass group relative flex flex-col gap-4 rounded-lg p-5 transition-all duration-300",
        colorMap[meta.color],
      )}
    >
      {/* Header */}
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-3">
          <div
            className={cn(
              "flex h-10 w-10 shrink-0 items-center justify-center rounded-lg transition-shadow duration-300",
              badgeBgMap[meta.color],
              `group-hover:${glowMap[meta.color]}`,
            )}
          >
            <Cpu className="h-5 w-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span
                className={cn(
                  "ui-chip ui-chip-sm ui-chip-pill font-bold",
                  badgeBgMap[meta.color],
                )}
              >
                <span className={cn("h-1.5 w-1.5 rounded-full", dotColorMap[meta.color])} />
                {meta.label}
              </span>
            </div>
            <p className="mt-1 text-[11px] text-muted-foreground">{meta.description}</p>
          </div>
        </div>
      </div>

      {/* Model Name */}
      <div className="rounded-md border border-border bg-card px-3 py-2.5">
        <div className="ui-label">
          Active Model
        </div>
        <div className="mt-1 truncate font-mono text-sm font-medium text-foreground" title={model.name}>
          {shortName}
        </div>
        {model.name !== shortName && (
          <div className="mt-0.5 truncate ui-meta text-muted-foreground/60" title={model.name}>
            {model.name}
          </div>
        )}
      </div>

      {/* Parameters */}
      <div className="grid grid-cols-2 gap-3">
        <div className="flex items-center gap-2 rounded-md border border-border bg-card px-3 py-2">
          <Thermometer className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
          <div>
            <div className="ui-label ui-label-xs">
              Temperature
            </div>
            <div className="font-mono text-sm tabular-nums text-foreground">
              {model.temperature}
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2 rounded-md border border-border bg-card px-3 py-2">
          <Hash className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
          <div>
            <div className="ui-label ui-label-xs">
              Max Tokens
            </div>
            <div className="font-mono text-sm tabular-nums text-foreground">
              {model.max_tokens.toLocaleString()}
            </div>
          </div>
        </div>
      </div>

      {/* Use For tags */}
      {model.use_for.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5">
          <Layers className="h-3 w-3 text-muted-foreground" />
          {model.use_for.map((u) => (
            <span
              key={u}
              className="ui-chip ui-chip-xs ui-chip-pill ui-chip-muted"
            >
              {u}
            </span>
          ))}
        </div>
      )}

      {/* Edit Button */}
      <button
        type="button"
        onClick={onEdit}
        className={cn(
          "mt-auto w-full rounded-md border border-border bg-card px-4 py-2 ui-label text-muted-foreground transition-all",
          "hover:border-primary/40 hover:bg-primary/10 hover:text-primary",
        )}
      >
        Configure Model
      </button>
    </div>
  );
}
