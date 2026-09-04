import json
import os
from datetime import datetime

from database import get_db_connection


MAX_HISTORY = 4


def _using_postgres():

    return bool(
        os.environ.get(
            "DATABASE_URL",
            ""
        ).strip()
    )


def _empty_history():

    return {
        "cloud_scans": [],
        "device_scans": []
    }


# ============================================================
# POSTGRESQL HISTORY TABLE
# ============================================================

def _create_history_table():

    connection = get_db_connection()

    try:

        if connection.is_postgres:

            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_history (
                    id SERIAL PRIMARY KEY,
                    scan_type TEXT NOT NULL,
                    scan_date TEXT NOT NULL,
                    scan_time TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    high_risks INTEGER NOT NULL DEFAULT 0,
                    medium_risks INTEGER NOT NULL DEFAULT 0,
                    low_risks INTEGER NOT NULL DEFAULT 0,
                    created_at TIMESTAMP
                    DEFAULT CURRENT_TIMESTAMP
                )
                """
            )

            connection.commit()

    finally:

        connection.close()


# ============================================================
# LOAD HISTORY
# ============================================================

def load_history():

    if _using_postgres():

        return {
            "cloud_scans": get_history(),
            "device_scans": get_device_history()
        }

    history_file = "scan_history.json"

    if not os.path.exists(history_file):

        return _empty_history()

    try:

        with open(
            history_file,
            "r",
            encoding="utf-8"
        ) as file:

            history = json.load(file)

        if isinstance(history, list):

            history = {
                "cloud_scans": history[:MAX_HISTORY],
                "device_scans": []
            }

        if "cloud_scans" not in history:

            history["cloud_scans"] = []

        if "device_scans" not in history:

            history["device_scans"] = []

        history["cloud_scans"] = (
            history["cloud_scans"][:MAX_HISTORY]
        )

        history["device_scans"] = (
            history["device_scans"][:MAX_HISTORY]
        )

        return history

    except Exception:

        return _empty_history()


# ============================================================
# SAVE CLOUD SCAN
# ============================================================

def save_scan(
    score,
    status,
    high_risks,
    medium_risks,
    low_risks
):

    now = datetime.now()

    if _using_postgres():

        _create_history_table()

        connection = get_db_connection()

        try:

            connection.execute(
                """
                INSERT INTO scan_history
                (
                    scan_type,
                    scan_date,
                    scan_time,
                    score,
                    status,
                    high_risks,
                    medium_risks,
                    low_risks
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "cloud",
                    now.strftime("%d-%m-%Y"),
                    now.strftime("%I:%M:%S %p"),
                    int(score),
                    str(status),
                    int(high_risks),
                    int(medium_risks),
                    int(low_risks)
                )
            )

            connection.commit()

        finally:

            connection.close()

        return

    history = load_history()

    new_scan = {

        "scan_number": 0,

        "date": now.strftime(
            "%d-%m-%Y"
        ),

        "time": now.strftime(
            "%I:%M:%S %p"
        ),

        "score": score,

        "status": status,

        "high": high_risks,

        "medium": medium_risks,

        "low": low_risks
    }

    history["cloud_scans"].insert(
        0,
        new_scan
    )

    history["cloud_scans"] = (
        history["cloud_scans"][:MAX_HISTORY]
    )

    for index, scan in enumerate(
        history["cloud_scans"],
        start=1
    ):

        scan["scan_number"] = index

    save_history(history)


# ============================================================
# SAVE DEVICE SCAN
# ============================================================

def save_device_scan(
    score,
    status,
    high_risks,
    medium_risks,
    low_risks
):

    now = datetime.now()

    if _using_postgres():

        _create_history_table()

        connection = get_db_connection()

        try:

            connection.execute(
                """
                INSERT INTO scan_history
                (
                    scan_type,
                    scan_date,
                    scan_time,
                    score,
                    status,
                    high_risks,
                    medium_risks,
                    low_risks
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "device",
                    now.strftime("%d-%m-%Y"),
                    now.strftime("%I:%M:%S %p"),
                    int(score),
                    str(status),
                    int(high_risks),
                    int(medium_risks),
                    int(low_risks)
                )
            )

            connection.commit()

        finally:

            connection.close()

        return

    history = load_history()

    new_scan = {

        "scan_number": 0,

        "date": now.strftime(
            "%d-%m-%Y"
        ),

        "time": now.strftime(
            "%I:%M:%S %p"
        ),

        "score": score,

        "status": status,

        "high": high_risks,

        "medium": medium_risks,

        "low": low_risks
    }

    history["device_scans"].insert(
        0,
        new_scan
    )

    history["device_scans"] = (
        history["device_scans"][:MAX_HISTORY]
    )

    for index, scan in enumerate(
        history["device_scans"],
        start=1
    ):

        scan["scan_number"] = index

    save_history(history)


# ============================================================
# SAVE SQLITE HISTORY
# ============================================================

def save_history(history):

    with open(
        "scan_history.json",
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            history,
            file,
            indent=4
        )


# ============================================================
# GET CLOUD HISTORY
# ============================================================

def get_history():

    if _using_postgres():

        _create_history_table()

        connection = get_db_connection()

        try:

            rows = connection.execute(
                """
                SELECT
                    id,
                    scan_date,
                    scan_time,
                    score,
                    status,
                    high_risks,
                    medium_risks,
                    low_risks
                FROM scan_history
                WHERE scan_type = ?
                ORDER BY created_at DESC, id DESC
                LIMIT ?
                """,
                (
                    "cloud",
                    MAX_HISTORY
                )
            ).fetchall()

            history = []

            for index, row in enumerate(
                rows,
                start=1
            ):

                history.append({

                    "scan_number": index,

                    "date": row["scan_date"],

                    "time": row["scan_time"],

                    "score": row["score"],

                    "status": row["status"],

                    "high": row["high_risks"],

                    "medium": row["medium_risks"],

                    "low": row["low_risks"]
                })

            return history

        finally:

            connection.close()

    history = load_history()

    return history.get(
        "cloud_scans",
        []
    )[:MAX_HISTORY]


# ============================================================
# GET DEVICE HISTORY
# ============================================================

def get_device_history():

    if _using_postgres():

        _create_history_table()

        connection = get_db_connection()

        try:

            rows = connection.execute(
                """
                SELECT
                    id,
                    scan_date,
                    scan_time,
                    score,
                    status,
                    high_risks,
                    medium_risks,
                    low_risks
                FROM scan_history
                WHERE scan_type = ?
                ORDER BY created_at DESC, id DESC
                LIMIT ?
                """,
                (
                    "device",
                    MAX_HISTORY
                )
            ).fetchall()

            history = []

            for index, row in enumerate(
                rows,
                start=1
            ):

                history.append({

                    "scan_number": index,

                    "date": row["scan_date"],

                    "time": row["scan_time"],

                    "score": row["score"],

                    "status": row["status"],

                    "high": row["high_risks"],

                    "medium": row["medium_risks"],

                    "low": row["low_risks"]
                })

            return history

        finally:

            connection.close()

    history = load_history()

    return history.get(
        "device_scans",
        []
    )[:MAX_HISTORY]