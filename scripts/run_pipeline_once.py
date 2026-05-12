from datetime import datetime, UTC

from app import create_app
from app.extensions import db
from app.jobs import run_full_pipeline
from app.models import AutomationRun

app = create_app()


def utc_now_naive():
    return datetime.now(UTC).replace(tzinfo=None)


def _format_summary(result):
    lines = ["pipeline complete:"]
    for stage in ("ingest", "enrich", "process", "extract", "cluster", "attribute", "audit"):
        seconds = result.get(f"{stage}_seconds")
        seconds_str = f"{seconds:.2f}s" if isinstance(seconds, (int, float)) else "n/a"
        if stage == "enrich":
            stats = result.get("enrich") or {}
            candidates = stats.get("candidates", 0)
            enriched = stats.get("enriched", 0)
            lines.append(
                f"  enrich    {seconds_str}  candidates={candidates} enriched={enriched}"
            )
        elif stage == "attribute":
            stats = result.get("attribute") or {}
            considered = stats.get("events_considered", 0)
            changed = stats.get("events_changed", 0)
            lines.append(
                f"  attribute {seconds_str}  considered={considered} changed={changed}"
            )
        elif stage == "audit":
            stats = result.get("audit") or {}
            scanned = stats.get("articles_scanned", 0)
            new = stats.get("new_sightings", 0)
            lines.append(
                f"  audit     {seconds_str}  scanned={scanned} new_sightings={new}"
            )
        else:
            ok = result.get(stage)
            lines.append(f"  {stage:<9} {seconds_str}  ok={ok}")
    return "\n".join(lines)


with app.app_context():
    run = AutomationRun(started_at=utc_now_naive())
    db.session.add(run)
    db.session.commit()

    try:
        result = run_full_pipeline(force_extract=False)

        run.finished_at = utc_now_naive()
        run.success = True
        run.result = result
        run.error = None

        db.session.commit()
        print(_format_summary(result))
    except Exception as exc:
        run.finished_at = utc_now_naive()
        run.success = False
        run.error = str(exc)

        db.session.commit()
        raise
