from history import load_history


# =========================================================
# LOAD DASHBOARD STATISTICS
# =========================================================

def load_stats():

    history = load_history()

    total_scans = len(history)

    safe_websites = 0

    phishing_websites = 0


    # =====================================================
    # COUNT RESULTS FROM HISTORY
    # =====================================================

    for scan in history:

        prediction = str(
            scan.get("prediction", "")
        ).upper().strip()


        if prediction == "PHISHING":

            phishing_websites += 1

        else:

            safe_websites += 1


    # =====================================================
    # RETURN STATISTICS
    # =====================================================

    return {

        "total_scans": total_scans,

        "safe_websites": safe_websites,

        "phishing_websites": phishing_websites
    }


# =========================================================
# UPDATE STATS
# =========================================================

# Kept for compatibility with older app.py files.
# Statistics are now calculated directly from history.

def update_stats(prediction):

    pass