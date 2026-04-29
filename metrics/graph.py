from __future__ import annotations

import json
from typing import Iterable

from attacks.brute_force import crack_time_for_length


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
