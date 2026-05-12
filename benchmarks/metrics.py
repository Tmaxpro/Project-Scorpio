"""Compute and display LLM usage metrics from ARIA benchmark JSONL logs.

Usage:
    python benchmarks/metrics.py [--runs-dir ./benchmarks/runs]
    python benchmarks/metrics.py --file benchmarks/runs/<scan_id>.jsonl
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ModelStats:
    """Aggregated statistics for a single model across all recorded calls."""

    model: str
    calls: int = 0
    successes: int = 0
    total_latency_ms: float = 0.0
    total_tokens_in: int = 0
    total_tokens_out: int = 0

    @property
    def success_rate(self) -> float:
        return self.successes / self.calls if self.calls else 0.0

    @property
    def avg_latency_ms(self) -> float:
        return self.total_latency_ms / self.calls if self.calls else 0.0


def load_file(path: str | Path) -> list[dict]:
    """Load all JSON entries from a single JSONL file; skip malformed lines."""
    entries: list[dict] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return entries


def load_dir(runs_dir: str | Path = "./benchmarks/runs") -> list[dict]:
    """Load all JSONL entries from every .jsonl file in *runs_dir*."""
    entries: list[dict] = []
    runs_path = Path(runs_dir)
    if not runs_path.exists():
        return entries
    for jsonl_file in sorted(runs_path.glob("*.jsonl")):
        entries.extend(load_file(jsonl_file))
    return entries


def compute_stats(entries: list[dict]) -> list[ModelStats]:
    """Aggregate per-model statistics from raw log entries."""
    by_model: dict[str, ModelStats] = {}
    for entry in entries:
        model = entry.get("model_used", "unknown")
        if model not in by_model:
            by_model[model] = ModelStats(model=model)
        stats = by_model[model]
        stats.calls += 1
        if entry.get("success"):
            stats.successes += 1
        stats.total_latency_ms += float(entry.get("latency_ms", 0))
        stats.total_tokens_in += int(entry.get("tokens_in", 0))
        stats.total_tokens_out += int(entry.get("tokens_out", 0))
    return sorted(by_model.values(), key=lambda s: s.calls, reverse=True)


def compute_task_type_stats(entries: list[dict]) -> dict[str, dict]:
    """Aggregate per-task-type statistics (reason / instruct / fallback)."""
    by_type: dict[str, dict] = defaultdict(lambda: {"calls": 0, "successes": 0, "total_latency_ms": 0.0})
    for entry in entries:
        t = entry.get("task_type", "unknown")
        by_type[t]["calls"] += 1
        if entry.get("success"):
            by_type[t]["successes"] += 1
        by_type[t]["total_latency_ms"] += float(entry.get("latency_ms", 0))
    return dict(by_type)


def format_summary(
    stats: list[ModelStats],
    entries: list[dict],
    runs_dir: str = "",
) -> str:
    """Render a human-readable text table."""
    lines: list[str] = [
        "═" * 72,
        "  ARIA LLM Usage Metrics",
        f"  Source: {runs_dir or 'provided entries'}  —  {len(entries)} total calls",
        "═" * 72,
    ]

    if not stats:
        lines.append("  No data.")
        lines.append("═" * 72)
        return "\n".join(lines)

    # Per-model table
    col = "{:<45} {:>6} {:>8} {:>10} {:>10}"
    lines += [
        col.format("Model", "Calls", "Success%", "Avg ms", "Tok Out"),
        "─" * 72,
    ]
    for s in stats:
        lines.append(col.format(
            s.model[:44],
            s.calls,
            f"{s.success_rate * 100:.0f}%",
            f"{s.avg_latency_ms:.1f}",
            s.total_tokens_out,
        ))

    # Per-task-type summary
    tt = compute_task_type_stats(entries)
    if tt:
        lines += ["─" * 72, "  By task type:"]
        for task_type, d in sorted(tt.items()):
            avg = d["total_latency_ms"] / d["calls"] if d["calls"] else 0
            lines.append(
                f"    {task_type:<12}  calls={d['calls']:>4}  "
                f"ok={d['successes']:>4}  avg={avg:.1f} ms"
            )

    lines.append("═" * 72)
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="ARIA benchmark metrics viewer")
    parser.add_argument("--runs-dir", default="./benchmarks/runs", help="Directory of JSONL run files")
    parser.add_argument("--file", default="", help="Single JSONL file to analyse")
    args = parser.parse_args()

    if args.file:
        entries = load_file(args.file)
        src = args.file
    else:
        entries = load_dir(args.runs_dir)
        src = args.runs_dir

    stats = compute_stats(entries)
    print(format_summary(stats, entries, runs_dir=src))


if __name__ == "__main__":
    main()
