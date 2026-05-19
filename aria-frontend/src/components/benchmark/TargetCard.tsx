import { useState } from "react";
import {
  ChevronDown,
  ChevronUp,
  ExternalLink,
  ShieldCheck,
  ShieldAlert,
  ShieldQuestion,
  Github,
  FileText,
} from "lucide-react";
import type { TargetAPIConfig } from "@/lib/types";
import { cn } from "@/lib/utils";

interface TargetCardProps {
  config: TargetAPIConfig;
  selected: boolean;
  onSelect: () => void;
  onLoadSpec?: () => void;
}

const DIFFICULTY_STYLE: Record<TargetAPIConfig["difficulty"], string> = {
  easy: "border-success/40 bg-success/10 text-success",
  medium: "border-warning/40 bg-warning/10 text-warning",
  hard: "border-danger/40 bg-danger/10 text-danger",
};

export function TargetCard({ config, selected, onSelect, onLoadSpec }: TargetCardProps) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div
      onClick={onSelect}
      className={cn(
        "glass relative cursor-pointer rounded-lg border-2 p-5 transition-all duration-150",
        selected
          ? "border-primary glow-cyan"
          : "border-transparent hover:border-border",
      )}
    >
      {/* Header */}
      <div className="mb-3 flex items-start justify-between gap-2">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <h3 className="text-xl font-semibold text-foreground">{config.name}</h3>
            <span
              className={cn(
                "ui-chip ui-chip-xs",
                DIFFICULTY_STYLE[config.difficulty],
              )}
            >
              {config.difficulty}
            </span>
          </div>
          <p className="mt-0.5 truncate ui-label">
            by {config.author}
          </p>
        </div>
        <a
          href={config.github_url}
          target="_blank"
          rel="noreferrer"
          onClick={(e) => e.stopPropagation()}
          className="shrink-0 rounded-md p-1.5 text-muted-foreground hover:bg-surface-hover hover:text-foreground"
          aria-label="View on GitHub"
        >
          <Github className="h-4 w-4" />
        </a>
      </div>

      {/* Description */}
      <p className="mb-4 text-xs text-muted-foreground">{config.description}</p>

      {/* Vulns count */}
      <div className="mb-3 flex items-center gap-2 font-mono text-[11px] text-foreground">
        <ShieldAlert className="h-3.5 w-3.5 text-warning" />
        <span className="tabular-nums">{config.total_vulns}</span>
        <span className="text-muted-foreground">known vulnerabilities</span>
      </div>

      {/* OWASP coverage pills */}
      <div className="mb-3 flex flex-wrap gap-1">
        {config.owasp_coverage.map((cat) => (
          <span
            key={cat}
            className="ui-chip ui-chip-xs ui-chip-muted"
          >
            {cat}
          </span>
        ))}
      </div>

      {/* Secure mode + Spec availability */}
      <div className="mb-3 flex flex-wrap gap-2">
        {config.has_secure_mode && (
          <span
            title={config.secure_mode_note}
            className="ui-chip ui-chip-xs border-primary/40 bg-primary/10 text-primary"
          >
            <ShieldCheck className="h-3 w-3" />
            Secure mode
          </span>
        )}
        {config.openapi_spec.available ? (
          <span className="ui-chip ui-chip-xs border-success/40 bg-success/10 text-success">
            <FileText className="h-3 w-3" />
            Official spec
          </span>
        ) : (
          <span className="ui-chip ui-chip-xs border-warning/40 bg-warning/10 text-warning">
            <ShieldQuestion className="h-3 w-3" />
            Spec manual
          </span>
        )}
      </div>

      {/* Load spec button — only when spec URL is fetchable */}
      {selected && config.openapi_spec.available && config.openapi_spec.url && onLoadSpec && (
        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            onLoadSpec();
          }}
          className="mb-3 inline-flex w-full items-center justify-center gap-2 rounded-md border border-primary/40 bg-primary/10 px-3 py-1.5 ui-label text-primary transition-colors hover:bg-primary/20"
        >
          <ExternalLink className="h-3 w-3" />
          Load official spec
        </button>
      )}

      {/* Setup instructions toggle */}
      <button
        type="button"
        onClick={(e) => {
          e.stopPropagation();
          setExpanded((v) => !v);
        }}
        className="flex w-full items-center justify-between gap-1 rounded-md border border-border bg-card px-3 py-1.5 ui-label transition-colors hover:bg-surface-hover hover:text-foreground"
      >
        <span>Setup instructions</span>
        {expanded ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
      </button>

      {expanded && (
        <div className="ui-panel ui-panel-compact mt-3 space-y-2">
          <CodeLine label="Vulnerable mode" code={config.docker_setup.primary} />
          {config.docker_setup.secure_mode && (
            <CodeLine label="Secure mode" code={config.docker_setup.secure_mode} />
          )}
          <p className="ui-meta italic text-muted-foreground">
            {config.docker_setup.note}
          </p>
        </div>
      )}
    </div>
  );
}

function CodeLine({ label, code }: { label: string; code: string }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    void navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };
  return (
    <div>
      <div className="mb-1 ui-label ui-label-xs">
        {label}
      </div>
      <button
        type="button"
        onClick={(e) => {
          e.stopPropagation();
          copy();
        }}
        title={copied ? "Copied!" : "Click to copy"}
        className="block w-full overflow-x-auto ui-codeblock text-left hover:bg-surface-hover"
      >
        <code className="whitespace-pre">{code}</code>
        {copied && (
          <div className="mt-1 ui-label-xs text-success">✓ Copied</div>
        )}
      </button>
    </div>
  );
}
