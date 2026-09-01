import json
import os
from datetime import datetime


HISTORY_FILE = "scan_history.json"

MAX_HISTORY = 4


# ==========================================
# LOAD COMPLETE HISTORY
# ==========================================

def load_history():

    # Create empty history structure if file
    # does not exist

    if not os.path.exists(HISTORY_FILE):

        return {

            "cloud_scans": [],

            "device_scans": []

        }


    try:

        with open(HISTORY_FILE, "r") as file:

            history = json.load(file)


        # ==================================
        # SUPPORT OLD HISTORY FORMAT
        # ==================================

        # Your old JSON file contains a list.
        # Convert it automatically.

        if isinstance(history, list):

            history = {

                "cloud_scans": history[:MAX_HISTORY],

                "device_scans": []

            }


        # ==================================
        # MAKE SURE KEYS EXIST
        # ==================================

        if "cloud_scans" not in history:

            history["cloud_scans"] = []


        if "device_scans" not in history:

            history["device_scans"] = []


        # ==================================
        # KEEP ONLY LATEST 4
        # ==================================

        history["cloud_scans"] = (
            history["cloud_scans"][:MAX_HISTORY]
        )

        history["device_scans"] = (
            history["device_scans"][:MAX_HISTORY]
        )


        return history


    except Exception:

        return {

            "cloud_scans": [],

            "device_scans": []

        }


# ==========================================
# SAVE CLOUD SECURITY SCAN
# ==========================================

def save_scan(

    score,

    status,

    high_risks,

    medium_risks,

    low_risks

):

    history = load_history()


    # ======================================
    # CREATE NEW CLOUD SCAN
    # ======================================

    new_scan = {

        "scan_number": 0,

        "date": datetime.now().strftime(
            "%d-%m-%Y"
        ),

        "time": datetime.now().strftime(
            "%I:%M:%S %p"
        ),

        "score": score,

        "status": status,

        "high": high_risks,

        "medium": medium_risks,

        "low": low_risks

    }


    # ======================================
    # ADD TO TOP
    # ======================================

    history["cloud_scans"].insert(

        0,

        new_scan

    )


    # ======================================
    # KEEP ONLY LATEST 4
    # ======================================

    history["cloud_scans"] = (
        history["cloud_scans"][:MAX_HISTORY]
    )


    # ======================================
    # UPDATE SCAN NUMBERS
    # ======================================

    for index, scan in enumerate(

        history["cloud_scans"],

        start=1

    ):

        scan["scan_number"] = index


    # ======================================
    # SAVE FILE
    # ======================================

    save_history(history)


# ==========================================
# SAVE DEVICE SECURITY SCAN
# ==========================================

def save_device_scan(

    score,

    status,

    high_risks,

    medium_risks,

    low_risks

):

    history = load_history()


    # ======================================
    # CREATE NEW DEVICE SCAN
    # ======================================

    new_scan = {

        "scan_number": 0,

        "date": datetime.now().strftime(
            "%d-%m-%Y"
        ),

        "time": datetime.now().strftime(
            "%I:%M:%S %p"
        ),

        "score": score,

        "status": status,

        "high": high_risks,

        "medium": medium_risks,

        "low": low_risks

    }


    # ======================================
    # ADD NEW SCAN TO TOP
    # ======================================

    history["device_scans"].insert(

        0,

        new_scan

    )


    # ======================================
    # KEEP ONLY LATEST 4
    # ======================================

    history["device_scans"] = (
        history["device_scans"][:MAX_HISTORY]
    )


    # ======================================
    # UPDATE SCAN NUMBERS
    # ======================================

    for index, scan in enumerate(

        history["device_scans"],

        start=1

    ):

        scan["scan_number"] = index


    # ======================================
    # SAVE COMPLETE HISTORY
    # ======================================

    save_history(history)


# ==========================================
# SAVE HISTORY FILE
# ==========================================

def save_history(history):

    with open(

        HISTORY_FILE,

        "w"

    ) as file:

        json.dump(

            history,

            file,

            indent=4

        )


# ==========================================
# GET CLOUD SCAN HISTORY
# ==========================================

def get_history():

    history = load_history()


    return history.get(

        "cloud_scans",

        []

    )[:MAX_HISTORY]


# ==========================================
# GET DEVICE SCAN HISTORY
# ==========================================

def get_device_history():

    history = load_history()


    return history.get(

        "device_scans",

        []

    )[:MAX_HISTORY]