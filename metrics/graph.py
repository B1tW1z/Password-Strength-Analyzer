from __future__ import annotations

import json
from typing import Iterable

from attacks.brute_force import crack_time_for_length


def _human_readable_seconds_for_graph(s: float) -> str:
    """Convert seconds to human-readable format for display in charts."""
    try:
        s = float(s)
    except Exception:
        return str(s)
    if s < 1:
        return f"{s:.3f}s"
    units = [(60 * 60 * 24 * 365, "yr"), (60 * 60 * 24, "d"), (3600, "h"), (60, "m"), (1, "s")]
    for div, suffix in units:
        if s >= div and div >= 1:
            val = s / div
            if val >= 1000:
                return f"{val:,.0f}{suffix}"
            elif val >= 100:
                return f"{val:.1f}{suffix}"
            else:
                return f"{val:.2f}{suffix}"
    return f"{s:.2f}s"


def build_chart_data(series: Iterable[dict[str, object]], attempts_per_second: int = 1_000_000) -> str:
    """
    Build Chart.js compatible data structure for rendering crack time curves.
    Returns JSON string of chart data.
    """
    datasets = []
    colors = [
        "rgb(99, 102, 241)",    # indigo
        "rgb(239, 68, 68)",     # red
        "rgb(34, 197, 94)",     # green
        "rgb(168, 85, 247)",    # purple
        "rgb(251, 146, 60)",    # orange
    ]

    series_list = list(series)
    for idx, item in enumerate(series_list):
        label = str(item["label"])
        password_length = int(item["password_length"])
        charset_size = int(item["charset_size"])
        max_length = max(12, password_length)
        lengths = list(range(1, max_length + 1))
        times = [crack_time_for_length(length, charset_size, attempts_per_second) for length in lengths]
        
        color = colors[idx % len(colors)]
        datasets.append({
            "label": label,
            "data": times,
            "borderColor": color,
            "backgroundColor": color.replace("rgb", "rgba").replace(")", ", 0.1)"),
            "borderWidth": 2,
            "tension": 0.4,
            "fill": False,
        })

    # Get x-axis labels (password lengths)
    if series_list:
        max_length = max(12, max(int(item["password_length"]) for item in series_list))
        labels = list(range(1, max_length + 1))
    else:
        labels = list(range(1, 13))

    chart_data = {
        "labels": labels,
        "datasets": datasets,
    }
    return json.dumps(chart_data)


def build_password_length_bar_chart(charset_size: int, attempts_per_second: int = 1_000_000) -> str:
    """
    Build Chart.js compatible horizontal bar chart for password length vs cracking time (lengths 6-18).
    Returns JSON string of chart data with human-readable labels.
    """
    lengths = list(range(6, 19))  # 6 to 18 characters
    times = [crack_time_for_length(length, charset_size, attempts_per_second) for length in lengths]
    
    # Create human-readable labels for bars
    bar_labels = [f"{length} chars: {_human_readable_seconds_for_graph(t)}" for length, t in zip(lengths, times)]
    
    # Color gradient: green (safe) to red (weak)
    colors_gradient = [
        "rgba(34, 197, 94, 0.8)",    # green (6 chars, quickest)
        "rgba(34, 197, 94, 0.75)",
        "rgba(251, 146, 60, 0.8)",   # orange
        "rgba(251, 146, 60, 0.75)",
        "rgba(239, 68, 68, 0.8)",    # red (harder)
        "rgba(239, 68, 68, 0.75)",
        "rgba(239, 68, 68, 0.7)",
        "rgba(168, 85, 247, 0.8)",   # purple (very hard)
        "rgba(168, 85, 247, 0.75)",
        "rgba(99, 102, 241, 0.8)",   # indigo (extremely hard)
        "rgba(99, 102, 241, 0.75)",
        "rgba(99, 102, 241, 0.7)",
        "rgba(99, 102, 241, 0.65)",
    ]
    
    chart_data = {
        "labels": [f"{l} chars" for l in lengths],
        "datasets": [
            {
                "label": "Estimated crack time",
                "data": times,
                "backgroundColor": colors_gradient,
                "borderColor": "rgba(17, 17, 17, 0.5)",
                "borderWidth": 1,
            }
        ],
    }
    return json.dumps(chart_data)
