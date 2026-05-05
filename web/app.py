from __future__ import annotations

import json
import math
import os
import queue
import threading
import time
import uuid
from pathlib import Path

from attacks.brute_force import CHARSETS
from attacks.brute_force import analyze as brute_force_analyze
from attacks.dictionary import simulate as dictionary_simulate
from flask import (Flask, Response, render_template, request,
                   stream_with_context)
from metrics.graph import build_chart_data, build_password_length_bar_chart
from metrics.tracker import AnalysisRecord, ResultTracker
from strength.aggregator import aggregate
from strength.entropy import estimate as entropy_estimate
from strength.generator import generate as generate_password
from strength.rule_based import analyze as rule_based_analyze
from strength.zxcvbn_adapter import analyze as zxcvbn_analyze

BASE_DIR = Path(__file__).resolve().parent.parent
WORDLIST_PATH = BASE_DIR / "data" / "default_wordlist.txt"
TRACKER_PATH = BASE_DIR / "data" / "results.json"
DEFAULT_WORDLIST_LABEL = "default"
UPLOAD_WORDLIST_LABEL = "upload"
DUAL_WORDLIST_LABEL = "both"


def _default_context() -> dict[str, object]:
    return {
        "history": [],
        "wordlist_mode": DEFAULT_WORDLIST_LABEL,
        "charset_name": "full",
        "password": "",
        "compare_passwords": "",
    }


def _read_wordlist_file(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _read_uploaded_wordlist(uploaded_file) -> list[str]:
    if not uploaded_file or not uploaded_file.filename:
        return []
    content = uploaded_file.read().decode("utf-8", errors="ignore")
    return [line.strip() for line in content.splitlines() if line.strip()]


def _resolve_wordlists(mode: str, uploaded_file) -> tuple[list[str], str]:
    default_words = _read_wordlist_file(WORDLIST_PATH)
    uploaded_words = _read_uploaded_wordlist(uploaded_file)

    if mode == UPLOAD_WORDLIST_LABEL:
        return uploaded_words, "Uploaded wordlist" if uploaded_words else "Upload selected, but no file was provided"

    if mode == DUAL_WORDLIST_LABEL:
        merged = default_words + [word for word in uploaded_words if word not in default_words]
        return merged, "Default + uploaded wordlist"

    return default_words, "Default bundled wordlist"


def _build_analysis_record(
    password: str,
    charset_name: str,
    aggregated,
    dictionary_result,
    brute_force_result,
) -> AnalysisRecord:
    return AnalysisRecord(
        password_length=len(password),
        charset_name=charset_name,
        charset_size=brute_force_result.charset_size,
        final_score=aggregated.final_score,
        rating=aggregated.rating,
        dictionary_matched=bool(dictionary_result and dictionary_result.matched),
        dictionary_match_type=dictionary_result.match_type if dictionary_result else "none",
        dictionary_time_seconds=dictionary_result.elapsed_seconds if dictionary_result else 0.0,
        brute_force_mode=brute_force_result.mode,
        brute_force_estimated_seconds=brute_force_result.estimated_seconds,
        brute_force_actual_seconds=brute_force_result.actual_seconds,
        entropy_bits=aggregated.entropy_bits,
    )


def _history_cards(history: list[dict[str, object]]) -> list[dict[str, object]]:
    return [
        {
            "rating": item.get("rating", "Weak"),
            "final_score": item.get("final_score", 0),
            "password_length": item.get("password_length", 0),
            "charset_name": item.get("charset_name", "full"),
        }
        for item in history
    ]


def _build_compare_series(password: str, charset_name: str, compare_passwords: str) -> list[dict[str, object]]:
    passwords = [password]
    passwords.extend([line.strip() for line in compare_passwords.splitlines() if line.strip()])

    series = []
    for index, candidate in enumerate(passwords, start=1):
        charset_size = len(CHARSETS.get(charset_name, CHARSETS["full"]))
        series.append(
            {
                "label": f"Sample {index} ({len(candidate)} chars)",
                "password_length": len(candidate),
                "charset_size": charset_size,
            }
        )
    return series


def _comparison_meter_items(dictionary_result, brute_force_result) -> list[dict[str, object]]:
    items: list[dict[str, object]] = []

    def _format_value(label: str, value: float) -> str:
        if value < 1:
            return f"{value:.6f}s"
        return f"{value:.2f}s"

    raw_values: list[tuple[str, float, str]] = [
        ("Dictionary", float(dictionary_result.elapsed_seconds) if dictionary_result else 0.0, "dict"),
        ("Brute-force estimate", float(brute_force_result.estimated_seconds) if brute_force_result else 0.0, "estimate"),
    ]
    if brute_force_result and brute_force_result.actual_seconds is not None:
        raw_values.append(("Brute-force actual", float(brute_force_result.actual_seconds), "actual"))

    positive_logs = [math.log10(max(value, 1e-6)) for _, value, _ in raw_values if value > 0]
    if not positive_logs:
        positive_logs = [0.0]

    min_log = min(positive_logs)
    max_log = max(positive_logs)

    for label, value, key in raw_values:
        log_value = math.log10(max(value, 1e-6)) if value > 0 else min_log
        if max_log == min_log:
            width_pct = 100.0
        else:
            width_pct = 12.0 + ((log_value - min_log) / (max_log - min_log)) * 88.0
        items.append(
            {
                "label": label,
                "key": key,
                "seconds": value,
                "display": _format_value(label, value),
                "width_pct": round(width_pct, 2),
            }
        )

    return items


def _human_readable_number(n: int) -> str:
    # Compact large integers (K, M, B, T)
    try:
        n = int(n)
    except Exception:
        return str(n)
    units = [(1_000_000_000_000, "T"), (1_000_000_000, "B"), (1_000_000, "M"), (1_000, "K")]
    for div, suffix in units:
        if n >= div:
            return f"{n/div:,.2f}{suffix}"
    return f"{n:,}"


def _human_readable_seconds(s: float) -> str:
    # Return a compact human readable time string
    try:
        s = float(s)
    except Exception:
        return str(s)
    if s < 1:
        return f"{s:.6f}s"
    units = [(60 * 60 * 24 * 365, "yr"), (60 * 60 * 24, "d"), (3600, "h"), (60, "m"), (1, "s")]
    for div, suffix in units:
        if s >= div and div >= 1:
            return f"{s/div:,.2f}{suffix}"
    return f"{s:.2f}s"


def _store_result(tracker: ResultTracker, record: AnalysisRecord) -> None:
    tracker.add(record)


def _render_page(template_name: str, tracker: ResultTracker, **context):
    base_context = _default_context()
    base_context.update(context)
    base_context["history"] = _history_cards(tracker.recent(6))
    return render_template(template_name, **base_context)


def create_app() -> Flask:
    app = Flask(__name__)
    tracker = ResultTracker(TRACKER_PATH)

    # In-memory run queues for streaming progress per run id
    run_queues: dict[str, queue.Queue] = {}

    @app.route("/", methods=["GET", "POST"])
    def home():
        if request.method == "POST":
            form_keys = set(request.form.keys())
            attack_fields = {"charset_name", "wordlist_mode", "compare_passwords", "case_variations"}
            if request.files.get("wordlist") or form_keys & attack_fields:
                return brute_force_page()
            return strength_page()

        return _render_page(
            "home.html",
            tracker,
            page_title="Home",
        )

    @app.route("/strength", methods=["GET", "POST"])
    def strength_page():
        context = {
            "page_title": "Strength Analysis",
            "password": "",
            "result": None,
            "insight": None,
        }

        if request.method == "POST":
            password = request.form.get("password", "")
            zxcvbn_result = zxcvbn_analyze(password)
            rule_result = rule_based_analyze(password)
            charset_size = len(CHARSETS["full"])
            entropy_result = entropy_estimate(password, charset_size)
            aggregated = aggregate(zxcvbn_result, rule_result, entropy_result)

            _store_result(
                tracker,
                _build_analysis_record(password, "full", aggregated, None, brute_force_analyze(password, "full")),
            )

            context.update(
                {
                    "password": password,
                    "result": aggregated,
                    "zxcvbn_result": zxcvbn_result,
                    "rule_result": rule_result,
                    "entropy_result": entropy_result,
                    "insight": zxcvbn_result.feedback or rule_result.feedback,
                    "suggested_password": generate_password(16),
                }
            )

        return _render_page("strength.html", tracker, **context)

    @app.route("/bruteforce", methods=["GET", "POST"])
    def brute_force_page():
        context = {
            "page_title": "Attack Simulation",
            "password": "",
            "charset_name": "full",
            "wordlist_mode": DEFAULT_WORDLIST_LABEL,
            "case_variations": True,
            "dictionary_result": None,
            "brute_force_result": None,
            "wordlist_source_label": "Default bundled wordlist",
            "compare_passwords": "",
        }

        if request.method == "POST":
            password = request.form.get("password", "")
            charset_name = request.form.get("charset_name", "full")
            # attempts per second selector (used for estimates and streaming simulation)
            try:
                attempts_per_second = float(request.form.get("attempts_per_second", "1000000"))
            except Exception:
                attempts_per_second = 1_000_000.0
            animate = request.form.get("animate") == "on"
            show_raw = request.form.get("show_raw") == "on"
            wordlist_mode = request.form.get("wordlist_mode", DEFAULT_WORDLIST_LABEL)
            compare_passwords = request.form.get("compare_passwords", "")
            case_variations = request.form.get("case_variations") == "on"
            uploaded_wordlist = request.files.get("wordlist")

            wordlist, wordlist_source_label = _resolve_wordlists(wordlist_mode, uploaded_wordlist)
            dictionary_result = dictionary_simulate(password, wordlist, case_variations=case_variations) if wordlist else None
            brute_force_result = brute_force_analyze(password, charset_name)

            zxcvbn_result = zxcvbn_analyze(password)
            rule_result = rule_based_analyze(password)
            entropy_result = entropy_estimate(password, brute_force_result.charset_size)
            aggregated = aggregate(zxcvbn_result, rule_result, entropy_result)

            _store_result(tracker, _build_analysis_record(password, charset_name, aggregated, dictionary_result, brute_force_result))

            # Build Chart.js data and inject measured points (dictionary/bruteforce actual times)
            raw_chart = build_chart_data(_build_compare_series(password, charset_name, compare_passwords), attempts_per_second=attempts_per_second)
            try:
                chart_json = json.loads(raw_chart)
            except Exception:
                chart_json = {"labels": [], "datasets": []}

            # Add measured series (place actual measured times at the password length index)
            labels = chart_json.get("labels", [])
            measured = [None] * len(labels)
            pw_len = len(password)
            if pw_len >= 1 and pw_len <= len(labels):
                idx = pw_len - 1
                # Prefer brute-force actual time if present, otherwise dictionary time
                if brute_force_result and brute_force_result.actual_seconds is not None:
                    measured[idx] = brute_force_result.actual_seconds
                elif dictionary_result and dictionary_result.elapsed_seconds is not None:
                    measured[idx] = dictionary_result.elapsed_seconds

            if any(v is not None for v in measured):
                chart_json.setdefault("datasets", []).append(
                    {
                        "label": "Measured (attack)",
                        "data": measured,
                        "borderColor": "rgba(17,17,17,0.9)",
                        "backgroundColor": "rgba(17,17,17,0.8)",
                        "pointRadius": 6,
                        "showLine": False,
                    }
                )

            chart_data = json.dumps(chart_json)

            # Generate bar chart data for password length vs cracking time (6-18 chars)
            bar_chart_data = build_password_length_bar_chart(brute_force_result.charset_size, attempts_per_second=attempts_per_second)

            # Human friendly strings for long numbers / times
            combinations_hr = _human_readable_number(brute_force_result.combinations)
            est_time_hr = _human_readable_seconds(brute_force_result.estimated_seconds)
            avg_time_hr = _human_readable_seconds(brute_force_result.estimated_seconds / 2)

            combinations_display = combinations_hr if not show_raw else str(combinations_raw)
            est_time_display = est_time_hr if not show_raw else f"{brute_force_result.estimated_seconds}"
            avg_time_display = avg_time_hr if not show_raw else f"{brute_force_result.estimated_seconds / 2}"

            # Raw values for toggle option
            combinations_raw = brute_force_result.combinations
            est_time_raw = brute_force_result.estimated_seconds

            # If animation requested, spawn a background thread to stream progress via SSE
            run_id = None
            if animate:
                run_id = uuid.uuid4().hex
                q = queue.Queue()
                run_queues[run_id] = q

                def worker_simulate(run_q: queue.Queue, pwd: str, attempts_per_sec: float):
                    # Simulate progressive measured times per password length up to the target length.
                    try:
                        target_len = max(1, len(pwd))
                        charset_size = brute_force_result.charset_size
                        for L in range(1, target_len + 1):
                            # estimate seconds for length L
                            combos = pow(charset_size, L)
                            est_sec = combos / max(1.0, attempts_per_sec)
                            # push an event with index and value
                            event = {"type": "progress", "length": L, "estimated_seconds": est_sec}
                            run_q.put(event)
                            time.sleep(0.25)
                        # final event
                        run_q.put({"type": "done"})
                    except Exception:
                        run_q.put({"type": "error", "message": "simulation error"})

                t = threading.Thread(target=worker_simulate, args=(q, password, attempts_per_second), daemon=True)
                t.start()

            context.update(
                {
                    "password": password,
                    "password_length": len(password),
                    "charset_name": charset_name,
                    "wordlist_mode": wordlist_mode,
                    "case_variations": case_variations,
                    "dictionary_result": dictionary_result,
                    "brute_force_result": brute_force_result,
                    "chart_data": chart_data,
                    "bar_chart_data": bar_chart_data,
                    "combinations_hr": combinations_hr,
                    "est_time_hr": est_time_hr,
                    "avg_time_hr": avg_time_hr,
                    "combinations_raw": combinations_raw,
                    "est_time_raw": est_time_raw,
                    "attempts_per_second": attempts_per_second,
                    "animate": animate,
                    "run_id": run_id,
                    "show_raw": show_raw,
                    "combinations_display": combinations_display,
                    "est_time_display": est_time_display,
                    "avg_time_display": avg_time_display,
                    "comparison_meter_items": _comparison_meter_items(dictionary_result, brute_force_result),
                    "wordlist_source_label": wordlist_source_label,
                    "compare_passwords": compare_passwords,
                    "result": aggregated,
                }
            )

        return _render_page("bruteforce.html", tracker, **context)

    @app.route("/history")
    def history_page():
        return _render_page("history.html", tracker, page_title="History")


    @app.route("/bruteforce/stream/<run_id>")
    def brute_force_stream(run_id: str):
        q = run_queues.get(run_id)
        if q is None:
            return ("", 404)

        def event_stream():
            # stream SSE events pulled from the run queue
            while True:
                try:
                    item = q.get(timeout=30)
                except queue.Empty:
                    # timeout — end stream
                    yield "event: done\n"
                    break
                data = json.dumps(item)
                yield f"data: {data}\n\n"
                if isinstance(item, dict) and item.get("type") in ("done", "error"):
                    break

        return Response(stream_with_context(event_stream()), mimetype="text/event-stream")

    @app.route("/faq")
    def faq_page():
        return _render_page("faq.html", tracker, page_title="FAQ")

    _ASSISTANT_SYSTEM_PROMPT = """You are an expert assistant for the Password Security Lab project.
Here is a full description of the project so you can answer questions about it accurately.

PROJECT OVERVIEW
================
Password Security Lab is a modular Flask web application that helps users understand
password strength and simulate common password-cracking attacks. It has four main pages:
Home, Strength, Attack Lab, History, FAQ, and this AI Assistant page.

MODULES & FILES
===============
strength/zxcvbn_adapter.py   — Wraps the zxcvbn library. Scores a password 0-4 and maps
                               it to a 0-100 scale. Returns pattern-based feedback.
strength/rule_based.py       — Checks composition rules: length bands, uppercase, lowercase,
                               digits, symbols. Returns a 0-100 score and improvement hints.
strength/entropy.py          — Estimates Shannon entropy (bits) given the password and the
                               active character-set size. Maps bits to a 0-100 score.
strength/aggregator.py       — Combines all three scores with weighted blending
                               (zxcvbn 40 %, rule-based 35 %, entropy 25 %) into a final
                               score and rating: Weak (<40), Medium (40-69), Strong (≥70).
strength/generator.py        — Generates a cryptographically secure suggested password
                               (16+ chars, guaranteed upper+lower+digit+symbol) using the
                               Python `secrets` module.
attacks/brute_force.py       — Estimates cracking time for four character sets
                               (digits, alpha, alphanumeric, full 95-char ASCII printable)
                               at a configurable attempts-per-second rate.
attacks/dictionary.py        — Simulates a dictionary attack against a bundled wordlist
                               (or user-uploaded list). Supports case-variation expansion.
metrics/tracker.py           — Persists every analysis result to data/results.json so the
                               History page can display recent runs.
metrics/graph.py             — Builds Chart.js-compatible JSON for the cracking-time line
                               chart and password-length bar chart shown on Attack Lab.
web/app.py                   — Flask application factory. Defines routes: /, /strength,
                               /bruteforce, /history, /faq, /assistant, and SSE streams.

STRENGTH PAGE
=============
Users type a password, click "Analyse Strength", and see:
- A final score (0-100) and rating badge (Weak / Medium / Strong).
- A colour-coded score bar.
- Individual scores from zxcvbn, rule-based, and entropy modules.
- A feedback/insight banner.
- A suggested strong password generated by strength/generator.py with a one-click copy button.

ATTACK LAB PAGE
===============
Users configure charset, wordlist, case-variations, attempts-per-second, and optionally
enable an animated streaming simulation via Server-Sent Events. Results include:
- Dictionary match result (matched / not matched, elapsed ms).
- Brute-force combination count and estimated / actual crack time.
- A line chart (password-length vs estimated crack time) and bar chart.
- A comparison meter showing relative times for each attack mode.

HISTORY PAGE
============
Shows the six most recent analyses with rating, score, password length, and charset.

FAQ PAGE
========
Static page explaining the methodology, scoring weights, and limitations (e.g. this tool
is not a replacement for multi-factor authentication or a proper password policy).

TECHNOLOGY STACK
================
- Python 3.x, Flask 3.0
- zxcvbn (pattern-based password scoring)
- passwordmeter
- llama-cpp-python (this AI assistant)
- Chart.js (visualisations, loaded via CDN)
- Vanilla HTML/CSS (neobrutalist design system in web/static/css/app.css)

Answer concisely and accurately. If asked something outside the project scope, say so politely.
"""

    # Lazy-load the llama model once and cache it
    _llama_model_cache: dict = {}

    def _get_llama_model():
        """Load and cache the Llama model. Returns (model, error_string)."""
        if "model" in _llama_model_cache:
            return _llama_model_cache["model"], None
        if "error" in _llama_model_cache:
            return None, _llama_model_cache["error"]

        model_path = os.environ.get("PSA_MODEL_PATH", "")
        if not model_path:
            err = (
                "PSA_MODEL_PATH environment variable is not set. "
                "Set it to the path of a GGUF model file, e.g.: "
                "export PSA_MODEL_PATH=/path/to/model.gguf"
            )
            _llama_model_cache["error"] = err
            return None, err

        if not Path(model_path).exists():
            err = f"Model file not found: {model_path}"
            _llama_model_cache["error"] = err
            return None, err

        try:
            from llama_cpp import Llama  # type: ignore
            model = Llama(
                model_path=model_path,
                n_ctx=2048,
                n_threads=os.cpu_count() or 4,
                verbose=False,
            )
            _llama_model_cache["model"] = model
            return model, None
        except Exception as exc:
            err = f"Failed to load model: {exc}"
            _llama_model_cache["error"] = err
            return None, err

    @app.route("/assistant", methods=["GET"])
    def assistant_page():
        _, model_error = _get_llama_model()
        return _render_page(
            "assistant.html",
            tracker,
            page_title="AI Assistant",
            model_error=model_error,
        )

    @app.route("/assistant/chat", methods=["POST"])
    def assistant_chat():
        """SSE endpoint — streams the LLM reply token by token."""
        data = request.get_json(silent=True) or {}
        user_message = (data.get("message") or "").strip()
        history = data.get("history") or []  # list of {role, content}

        if not user_message:
            return Response("data: {\"error\": \"Empty message\"}\n\n", mimetype="text/event-stream")

        model, model_error = _get_llama_model()

        def event_stream():
            if model_error:
                payload = json.dumps({"error": model_error})
                yield f"data: {payload}\n\n"
                return

            # Build messages array for chat completion
            messages = [{"role": "system", "content": _ASSISTANT_SYSTEM_PROMPT}]
            for entry in history[-10:]:  # keep last 10 turns for context
                role = entry.get("role", "user")
                content = entry.get("content", "")
                if role in ("user", "assistant") and content:
                    messages.append({"role": role, "content": content})
            messages.append({"role": "user", "content": user_message})

            try:
                stream = model.create_chat_completion(
                    messages=messages,
                    max_tokens=512,
                    temperature=0.7,
                    stream=True,
                )
                for chunk in stream:
                    delta = chunk.get("choices", [{}])[0].get("delta", {})
                    token = delta.get("content", "")
                    if token:
                        payload = json.dumps({"token": token})
                        yield f"data: {payload}\n\n"
                yield "data: {\"done\": true}\n\n"
            except Exception as exc:
                payload = json.dumps({"error": str(exc)})
                yield f"data: {payload}\n\n"

        return Response(stream_with_context(event_stream()), mimetype="text/event-stream")

    @app.errorhandler(404)
    def not_found(_error):
        return _render_page("not_found.html", tracker, page_title="Not Found"), 404

    return app


app = create_app()
