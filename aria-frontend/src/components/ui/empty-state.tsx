import type { ReactNode } from "react";
import type { LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";

interface EmptyStateProps {
  icon?: LucideIcon;
  title: string;
  description?: string;
  action?: ReactNode;
  className?: string;
  compact?: boolean;
}

export function EmptyState({
  icon: Icon,
  title,
  description,
  action,
  className,
  compact = false,
}: EmptyStateProps) {
  return (
    <div
      className={cn(
        "glass flex flex-col items-center justify-center rounded-lg text-center",
        compact ? "gap-2 p-6" : "gap-3 p-12",
        className,
      )}
    >
      {Icon && (
        <div className="relative mb-1">
          <div className="absolute inset-0 -z-10 rounded-full bg-cyan/10 blur-xl" />
          <Icon
            className={cn(
              "text-muted-foreground/60",
              compact ? "h-6 w-6" : "h-10 w-10",
            )}
            strokeWidth={1.25}
          />
        </div>
      )}
      <div
        className={cn(
          "font-mono uppercase tracking-widest text-foreground/80",
          compact ? "text-[11px]" : "text-xs",
        )}
      >
        {title}
      </div>
      {description && (
        <div className="max-w-sm text-xs text-muted-foreground">{description}</div>
      )}
      {action && <div className="mt-2">{action}</div>}
    </div>
  );
}
