from __future__ import annotations

from pathlib import Path

from flask import Flask, render_template, request
import json

from attacks.brute_force import CHARSETS, analyze as brute_force_analyze
from attacks.dictionary import simulate as dictionary_simulate
from metrics.graph import build_chart_data
from metrics.tracker import AnalysisRecord, ResultTracker
from strength.aggregator import aggregate
from strength.entropy import estimate as entropy_estimate
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
            "graph_html": None,
            "wordlist_source_label": "Default bundled wordlist",
            "compare_passwords": "",
        }

        if request.method == "POST":
            password = request.form.get("password", "")
            charset_name = request.form.get("charset_name", "full")
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
            raw_chart = build_chart_data(_build_compare_series(password, charset_name, compare_passwords))
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
                if brute_force_result and getattr(brute_force_result, "actual_seconds", None) is not None:
                    measured[idx] = brute_force_result.actual_seconds
                elif dictionary_result and getattr(dictionary_result, "elapsed_seconds", None) is not None:
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

            # Human friendly strings for long numbers / times
            combinations_hr = _human_readable_number(brute_force_result.combinations)
            est_time_hr = _human_readable_seconds(brute_force_result.estimated_seconds)

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
                    "combinations_hr": combinations_hr,
                    "est_time_hr": est_time_hr,
                    "wordlist_source_label": wordlist_source_label,
                    "compare_passwords": compare_passwords,
                    "result": aggregated,
                }
            )

        return _render_page("bruteforce.html", tracker, **context)

    @app.route("/history")
    def history_page():
        return _render_page("history.html", tracker, page_title="History")

    @app.route("/faq")
    def faq_page():
        return _render_page("faq.html", tracker, page_title="FAQ")

    @app.errorhandler(404)
    def not_found(_error):
        return _render_page("not_found.html", tracker, page_title="Not Found"), 404

    return app


app = create_app()
