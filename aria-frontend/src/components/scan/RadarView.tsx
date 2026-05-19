import { OWASP_META } from "@/lib/types";
import type { OWASPCategory, TaskResult } from "@/lib/types";

interface RadarViewProps {
  findings: TaskResult[];
  progress: number;
}

const CATEGORIES: OWASPCategory[] = [
  "API1", "API2", "API3", "API4", "API5",
  "API6", "API7", "API8", "API9", "API10",
];

const SEVERITY_FILL: Record<string, string> = {
  critical: "var(--sev-critical)",
  high: "var(--sev-high)",
  medium: "var(--sev-medium)",
  low: "var(--sev-low)",
  info: "var(--sev-info)",
};

export function RadarView({ findings, progress }: RadarViewProps) {
  const size = 320;
  const center = size / 2;
  const maxR = center - 24;

  const counts = CATEGORIES.map(
    (c) => findings.filter((f) => f.vuln_category === c).length,
  );
  const max = Math.max(1, ...counts);

  const points = CATEGORIES.map((c, i) => {
    const angle = (i / CATEGORIES.length) * Math.PI * 2 - Math.PI / 2;
    const r = (counts[i] / max) * maxR;
    return {
      cat: c,
      x: center + Math.cos(angle) * r,
      y: center + Math.sin(angle) * r,
      lx: center + Math.cos(angle) * (maxR + 14),
      ly: center + Math.sin(angle) * (maxR + 14),
      count: counts[i],
    };
  });

  const polygon = points.map((p) => `${p.x},${p.y}`).join(" ");

  return (
    <div className="glass relative flex flex-col items-center justify-center rounded-lg p-6">
      <div className="mb-2 flex w-full items-center justify-between">
        <h3 className="ui-label">
          Threat Radar
        </h3>
        <span className="font-mono text-xs text-cyan">
          {progress.toFixed(0)}%
        </span>
      </div>
      <svg
        viewBox={`0 0 ${size} ${size}`}
        className="h-[320px] w-[320px]"
        role="img"
        aria-label="OWASP API category radar"
      >
        {/* concentric rings */}
        {[0.25, 0.5, 0.75, 1].map((f) => (
          <circle
            key={f}
            cx={center}
            cy={center}
            r={maxR * f}
            fill="none"
            stroke="color-mix(in oklab, var(--cyan) 12%, transparent)"
            strokeWidth={1}
          />
        ))}
        {/* spokes */}
        {points.map((p, i) => {
          const angle = (i / CATEGORIES.length) * Math.PI * 2 - Math.PI / 2;
          return (
            <line
              key={p.cat}
              x1={center}
              y1={center}
              x2={center + Math.cos(angle) * maxR}
              y2={center + Math.sin(angle) * maxR}
              stroke="color-mix(in oklab, var(--cyan) 10%, transparent)"
              strokeWidth={1}
            />
          );
        })}
        {/* sweep beam */}
        <g className="origin-center animate-radar" style={{ transformOrigin: `${center}px ${center}px` }}>
          <defs>
            <linearGradient id="sweep" x1="0" y1="0" x2="1" y2="0">
              <stop offset="0%" stopColor="var(--cyan)" stopOpacity="0.6" />
              <stop offset="100%" stopColor="var(--cyan)" stopOpacity="0" />
            </linearGradient>
          </defs>
          <path
            d={`M${center},${center} L${center + maxR},${center} A${maxR},${maxR} 0 0 0 ${center + Math.cos(-0.6) * maxR},${center + Math.sin(-0.6) * maxR} Z`}
            fill="url(#sweep)"
          />
        </g>
        {/* data polygon */}
        <polygon
          points={polygon}
          fill="color-mix(in oklab, var(--violet) 18%, transparent)"
          stroke="var(--violet)"
          strokeWidth={1.5}
        />
        {/* finding dots */}
        {findings.slice(0, 30).map((f, idx) => {
          const i = CATEGORIES.indexOf(f.vuln_category);
          if (i < 0) return null;
          const angle = (i / CATEGORIES.length) * Math.PI * 2 - Math.PI / 2;
          const jitter = ((idx * 13) % 40) / 100;
          const r = maxR * (0.4 + jitter * 0.5);
          return (
            <circle
              key={f.task_id}
              cx={center + Math.cos(angle) * r}
              cy={center + Math.sin(angle) * r}
              r={3}
              fill={SEVERITY_FILL[f.severity]}
            >
              <animate
                attributeName="r"
                values="3;6;3"
                dur="1.6s"
                repeatCount="indefinite"
              />
            </circle>
          );
        })}
        {/* labels */}
        {points.map((p) => (
          <text
            key={p.cat}
            x={p.lx}
            y={p.ly}
            textAnchor="middle"
            dominantBaseline="middle"
            className="fill-muted-foreground font-mono"
            style={{ fontSize: 10 }}
          >
            {OWASP_META[p.cat].name.split(" ")[0]}
            {p.count > 0 && (
              <tspan className="fill-foreground" dx="3" fontWeight="600">
                {p.count}
              </tspan>
            )}
          </text>
        ))}
      </svg>
    </div>
  );
}
