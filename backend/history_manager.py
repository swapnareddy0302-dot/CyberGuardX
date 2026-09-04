# ============================================================
# CyberGuardX
# Scan History Manager
# Cloud + Device Scan History
# ============================================================

import json
import os
from datetime import datetime


HISTORY_FILE = "scan_history.json"

MAX_HISTORY = 4


# ============================================================
# CREATE EMPTY HISTORY
# ============================================================

def empty_history():

    return {
        "cloud_scans": [],
        "device_scans": []
    }


# ============================================================
# LOAD COMPLETE HISTORY
# ============================================================

def load_history():

    if not os.path.exists(HISTORY_FILE):
        return empty_history()

    try:

        with open(
            HISTORY_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            history = json.load(file)


        # ----------------------------------------------------
        # SUPPORT OLD LIST FORMAT
        # ----------------------------------------------------

        if isinstance(history, list):

            history = {

                "cloud_scans": history[:MAX_HISTORY],

                "device_scans": []

            }


        # ----------------------------------------------------
        # VALIDATE HISTORY
        # ----------------------------------------------------

        if not isinstance(history, dict):

            return empty_history()


        if "cloud_scans" not in history:

            history["cloud_scans"] = []


        if "device_scans" not in history:

            history["device_scans"] = []


        # ----------------------------------------------------
        # MAKE SURE VALUES ARE LISTS
        # ----------------------------------------------------

        if not isinstance(
            history["cloud_scans"],
            list
        ):

            history["cloud_scans"] = []


        if not isinstance(
            history["device_scans"],
            list
        ):

            history["device_scans"] = []


        # ----------------------------------------------------
        # KEEP ONLY LATEST SCANS
        # ----------------------------------------------------

        history["cloud_scans"] = (
            history["cloud_scans"][:MAX_HISTORY]
        )

        history["device_scans"] = (
            history["device_scans"][:MAX_HISTORY]
        )


        return history


    except (
        json.JSONDecodeError,
        OSError,
        TypeError,
        ValueError
    ):

        return empty_history()


# ============================================================
# SAVE COMPLETE HISTORY
# ============================================================

def save_history(history):

    try:

        with open(
            HISTORY_FILE,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                history,
                file,
                indent=4
            )

        return True

    except OSError:

        return False


# ============================================================
# CREATE SCAN RECORD
# ============================================================

def create_scan_record(

    score,

    status,

    high_risks,

    medium_risks,

    low_risks

):

    now = datetime.now()

    return {

        "scan_number": 0,

        "date": now.strftime(
            "%d-%m-%Y"
        ),

        "time": now.strftime(
            "%I:%M:%S %p"
        ),

        "score": int(score),

        "status": str(status),

        "high": int(high_risks),

        "medium": int(medium_risks),

        "low": int(low_risks)

    }


# ============================================================
# UPDATE SCAN NUMBERS
# ============================================================

def update_scan_numbers(scans):

    for index, scan in enumerate(
        scans,
        start=1
    ):

        if isinstance(scan, dict):

            scan["scan_number"] = index

    return scans


# ============================================================
# SAVE CLOUD SECURITY SCAN
# ============================================================

def save_scan(

    score,

    status,

    high_risks,

    medium_risks,

    low_risks

):

    history = load_history()


    # --------------------------------------------------------
    # CREATE NEW CLOUD RECORD
    # --------------------------------------------------------

    new_scan = create_scan_record(

        score,

        status,

        high_risks,

        medium_risks,

        low_risks

    )


    # --------------------------------------------------------
    # ADD TO TOP
    # --------------------------------------------------------

    history["cloud_scans"].insert(
        0,
        new_scan
    )


    # --------------------------------------------------------
    # KEEP LATEST 4
    # --------------------------------------------------------

    history["cloud_scans"] = (

        history["cloud_scans"]
        [:MAX_HISTORY]

    )


    # --------------------------------------------------------
    # UPDATE NUMBERS
    # --------------------------------------------------------

    history["cloud_scans"] = (
        update_scan_numbers(
            history["cloud_scans"]
        )
    )


    # --------------------------------------------------------
    # SAVE
    # --------------------------------------------------------

    save_history(history)


    # IMPORTANT:
    # Return the updated cloud history
    # so app.py can immediately display it.

    return history["cloud_scans"]


# ============================================================
# SAVE DEVICE SECURITY SCAN
# ============================================================

def save_device_scan(

    score,

    status,

    high_risks,

    medium_risks,

    low_risks

):

    history = load_history()


    # --------------------------------------------------------
    # CREATE NEW DEVICE RECORD
    # --------------------------------------------------------

    new_scan = create_scan_record(

        score,

        status,

        high_risks,

        medium_risks,

        low_risks

    )


    # --------------------------------------------------------
    # ADD TO TOP
    # --------------------------------------------------------

    history["device_scans"].insert(

        0,

        new_scan

    )


    # --------------------------------------------------------
    # KEEP LATEST 4
    # --------------------------------------------------------

    history["device_scans"] = (

        history["device_scans"]
        [:MAX_HISTORY]

    )


    # --------------------------------------------------------
    # UPDATE NUMBERS
    # --------------------------------------------------------

    history["device_scans"] = (
        update_scan_numbers(
            history["device_scans"]
        )
    )


    # --------------------------------------------------------
    # SAVE
    # --------------------------------------------------------

    save_history(history)


    # Return updated device history

    return history["device_scans"]


# ============================================================
# GET CLOUD SCAN HISTORY
# ============================================================

def get_history():

    history = load_history()

    return history.get(
        "cloud_scans",
        []
    )[:MAX_HISTORY]


# ============================================================
# GET DEVICE SCAN HISTORY
# ============================================================

def get_device_history():

    history = load_history()

    return history.get(
        "device_scans",
        []
    )[:MAX_HISTORY]