from app import create_app
from app.jobs import run_full_pipeline

app = create_app()

with app.app_context():
    result = run_full_pipeline(force_extract=False)
    print(result)