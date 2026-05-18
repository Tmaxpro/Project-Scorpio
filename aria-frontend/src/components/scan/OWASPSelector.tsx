import { OWASP_META, type OWASPCategory, type Severity } from "@/lib/types";
import { cn } from "@/lib/utils";

const CATEGORIES = Object.values(OWASP_META);

const RISK_STYLES: Record<Severity, string> = {
  critical: "border-sev-critical/50 bg-sev-critical/10 text-sev-critical",
  high: "border-sev-high/50 bg-sev-high/10 text-sev-high",
  medium: "border-sev-medium/50 bg-sev-medium/10 text-sev-medium",
  low: "border-sev-low/50 bg-sev-low/10 text-sev-low",
  info: "border-sev-info/50 bg-sev-info/10 text-sev-info",
};

interface OWASPSelectorProps {
  selected: OWASPCategory[];
  onChange: (selected: OWASPCategory[]) => void;
}

export function OWASPSelector({ selected, onChange }: OWASPSelectorProps) {
  const toggle = (c: OWASPCategory) =>
    onChange(selected.includes(c) ? selected.filter((x) => x !== c) : [...selected, c]);
  const allCodes = CATEGORIES.map((c) => c.code);
  const allSelected = selected.length === allCodes.length;

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="ui-label">
          OWASP API Security Top 10
        </h3>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => onChange(allSelected ? [] : allCodes)}
            className="ui-chip ui-chip-sm border-border text-muted-foreground hover:border-primary/50 hover:text-primary"
          >
            {allSelected ? "Deselect All" : "Select All"}
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5">
        {CATEGORIES.map((cat) => {
          const active = selected.includes(cat.code);
          return (
            <button
              key={cat.code}
              type="button"
              role="checkbox"
              aria-checked={active}
              onClick={() => toggle(cat.code)}
              className={cn(
                "group flex flex-col gap-2 rounded-md border p-3 text-left transition-all",
                active
                  ? "border-primary bg-primary/5"
                  : "border-border bg-card hover:border-primary/40 hover:bg-surface-hover",
              )}
            >
              <div className="flex items-center justify-between">
                <span
                  className={cn(
                    "font-mono text-[11px] font-bold tracking-wider",
                    active ? "text-primary" : "text-foreground",
                  )}
                >
                  {cat.code}
                </span>
                <span
                  className={cn(
                    "ui-chip ui-chip-xs",
                    RISK_STYLES[cat.risk],
                  )}
                >
                  {cat.risk}
                </span>
              </div>
              <div className="text-xs font-medium text-foreground">{cat.name}</div>
              <div className="flex items-center gap-1.5">
                <span
                  className={cn(
                    "flex h-3.5 w-3.5 items-center justify-center rounded-sm border transition-colors",
                    active ? "border-primary bg-primary" : "border-border bg-transparent",
                  )}
                >
                  {active && (
                    <svg viewBox="0 0 12 12" className="h-2.5 w-2.5 text-primary-foreground">
                      <path
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="2"
                        d="M2 6.5L5 9.5L10 3.5"
                      />
                    </svg>
                  )}
                </span>
                <span className="ui-label ui-label-xs">
                  {active ? "Enabled" : "Disabled"}
                </span>
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
}
