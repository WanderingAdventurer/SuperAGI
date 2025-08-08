# start.py
import os
import uvicorn
from superagi.lib.logger import logger

def run():
    logger.info("Bootstrapping… importing main.app directly")
    try:
        import main as main_module
        app = main_module.app   # use the object, NOT a string
    except Exception as e:
        logger.error(f"Failed to import main.app: {e}")
        raise

    port = int(os.getenv("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")

if __name__ == "__main__":
    run()
