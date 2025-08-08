import traceback, sys

print(">>> Bootstrapping… trying to import main.app")
try:
    import main  # this is your main.py
    from uvicorn import run
    print(">>> Import OK, starting Uvicorn…")
    run(main.app, host="0.0.0.0", port=8000, log_level="debug")
except Exception:
    print(">>> IMPORT FAILED! Full traceback below:", file=sys.stderr)
    traceback.print_exc()
    sys.exit(1)
