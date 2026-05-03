from datetime import datetime, UTC

from app import create_app
from app.extensions import db
from app.jobs import run_full_pipeline
from app.models import AutomationRun

app = create_app()


def utc_now_naive():
    return datetime.now(UTC).replace(tzinfo=None)


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
        print(result)
    except Exception as exc:
        run.finished_at = utc_now_naive()
        run.success = False
        run.error = str(exc)

        db.session.commit()
        raise