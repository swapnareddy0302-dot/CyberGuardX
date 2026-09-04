import platform
import socket
import os
import shutil
import sys
import uuid

from datetime import datetime


class DeviceScanner:

    """
    Read-only local device information collector
    for CyberGuardX.
    """


    # ========================================================
    # LOCAL IP
    # ========================================================

    def _local_ip(self):

        try:

            sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_DGRAM
            )

            sock.settimeout(0.5)

            sock.connect(
                (
                    "8.8.8.8",
                    80
                )
            )

            ip = sock.getsockname()[0]

            sock.close()

            return ip

        except Exception:

            try:

                return socket.gethostbyname(
                    socket.gethostname()
                )

            except Exception:

                return "Unavailable"


    # ========================================================
    # MAC ADDRESS
    # ========================================================

    def _mac(self):

        try:

            node = uuid.getnode()

            return ":".join(
                f"{(node >> shift) & 255:02x}"
                for shift in range(
                    40,
                    -1,
                    -8
                )
            )

        except Exception:

            return "Unavailable"


    # ========================================================
    # SCAN
    # ========================================================

    def scan(self):

        results = []


        # ----------------------------------------------------
        # OPERATING SYSTEM
        # ----------------------------------------------------

        operating_system = platform.system()

        release = platform.release()

        version = platform.version()


        results.append({

            "category":
                "Operating System",

            "finding":
                operating_system,

            "details":
                f"Release: {release} | Version: {version}",

            "risk":
                "Low"

        })


        # ----------------------------------------------------
        # HOSTNAME
        # ----------------------------------------------------

        hostname = socket.gethostname()


        results.append({

            "category":
                "System Identity",

            "finding":
                hostname,

            "details":
                "Device hostname detected successfully.",

            "risk":
                "Low"

        })


        # ----------------------------------------------------
        # IP ADDRESS
        # ----------------------------------------------------

        ip_address = self._local_ip()


        if ip_address in (
            "Unavailable",
            "127.0.0.1"
        ):

            ip_risk = "Medium"

        else:

            ip_risk = "Low"


        results.append({

            "category":
                "Network",

            "finding":
                "Local IP Address",

            "details":
                f"Detected IP address: {ip_address}",

            "risk":
                ip_risk

        })


        # ----------------------------------------------------
        # MAC ADDRESS
        # ----------------------------------------------------

        results.append({

            "category":
                "Network",

            "finding":
                "MAC Address",

            "details":
                self._mac(),

            "risk":
                "Low"

        })


        # ----------------------------------------------------
        # STORAGE
        # ----------------------------------------------------

        try:

            if os.name == "nt":

                disk_path = (
                    os.environ.get(
                        "SystemDrive",
                        "C:"
                    )
                    + "\\"
                )

            else:

                disk_path = "/"


            total, used, free = (
                shutil.disk_usage(
                    disk_path
                )
            )


            usage_percentage = (
                used / total
            ) * 100


            if usage_percentage > 90:

                risk = "High"

            elif usage_percentage > 80:

                risk = "Medium"

            else:

                risk = "Low"


            results.append({

                "category":
                    "Storage",

                "finding":
                    "Disk Usage",

                "details":
                    (
                        f"{usage_percentage:.1f}% used | "
                        f"{free / (1024 ** 3):.1f} GB free "
                        f"of {total / (1024 ** 3):.1f} GB"
                    ),

                "risk":
                    risk

            })

        except Exception as error:

            results.append({

                "category":
                    "Storage",

                "finding":
                    "Disk Scan",

                "details":
                    str(error),

                "risk":
                    "Medium"

            })


        # ----------------------------------------------------
        # USER
        # ----------------------------------------------------

        try:

            username = os.getlogin()

        except Exception:

            username = (
                os.environ.get("USERNAME")
                or os.environ.get("USER")
                or "Unknown User"
            )


        results.append({

            "category":
                "User Security",

            "finding":
                username,

            "details":
                "Current active device user detected.",

            "risk":
                "Low"

        })


        # ----------------------------------------------------
        # ARCHITECTURE
        # ----------------------------------------------------

        results.append({

            "category":
                "System Architecture",

            "finding":
                platform.machine()
                or "Unknown",

            "details":
                "Processor architecture detected.",

            "risk":
                "Low"

        })


        # ----------------------------------------------------
        # PROCESSOR
        # ----------------------------------------------------

        results.append({

            "category":
                "Hardware",

            "finding":
                "Processor",

            "details":
                platform.processor()
                or "Unavailable",

            "risk":
                "Low"

        })


        # ----------------------------------------------------
        # CPU CORES
        # ----------------------------------------------------

        results.append({

            "category":
                "Hardware",

            "finding":
                "CPU Cores",

            "details":
                (
                    f"{os.cpu_count() or 'Unknown'} "
                    "logical CPU cores detected."
                ),

            "risk":
                "Low"

        })


        # ----------------------------------------------------
        # PYTHON VERSION
        # ----------------------------------------------------

        results.append({

            "category":
                "Runtime",

            "finding":
                "Python Version",

            "details":
                sys.version.split()[0],

            "risk":
                "Low"

        })


        # ----------------------------------------------------
        # HOSTNAME RESOLUTION
        # ----------------------------------------------------

        results.append({

            "category":
                "Network Stack",

            "finding":
                "Hostname Resolution",

            "details":
                "Local hostname and IP resolution completed.",

            "risk":
                "Low"

        })


        # ----------------------------------------------------
        # SCAN TIME
        # ----------------------------------------------------

        scan_time = datetime.now().strftime(
            "%d-%m-%Y %I:%M:%S %p"
        )


        results.append({

            "category":
                "Scan Information",

            "finding":
                "Device Scan Completed",

            "details":
                scan_time,

            "risk":
                "Low"

        })


        return results