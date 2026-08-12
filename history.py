import json
import os
from datetime import datetime

HISTORY_FILE = "history.json"


# =========================================================
# LOAD HISTORY
# =========================================================

def load_history():

    if not os.path.exists(HISTORY_FILE):
        return []

    try:

        with open(HISTORY_FILE, "r", encoding="utf-8") as file:
            history = json.load(file)

        if isinstance(history, list):
            return history

        return []

    except (json.JSONDecodeError, FileNotFoundError):

        return []


# =========================================================
# SAVE HISTORY
# =========================================================

def save_history(history):

    with open(HISTORY_FILE, "w", encoding="utf-8") as file:

        json.dump(
            history,
            file,
            indent=4,
            ensure_ascii=False
        )


# =========================================================
# ADD NEW SCAN
# =========================================================

def add_history(url, prediction, score):

    history = load_history()

    scan = {

        "time": datetime.now().strftime(
            "%d-%m-%Y %H:%M:%S"
        ),

        "url": url,

        "prediction": prediction,

        "score": score
    }

    # Newest scan appears first
    history.insert(0, scan)

    save_history(history)


# =========================================================
# GET RECENT HISTORY
# =========================================================

def get_recent_history(limit=50):

    history = load_history()

    return history[:limit]