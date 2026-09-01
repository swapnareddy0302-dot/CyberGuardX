
import platform
import socket
import os
import shutil
from datetime import datetime


class DeviceScanner:

    def scan(self):

        results = []

        # =====================================
        # OPERATING SYSTEM CHECK
        # =====================================

        os_name = platform.system()
        os_version = platform.version()

        results.append({

            "category": "Operating System",

            "finding": os_name,

            "details": f"Operating system version detected: {os_version}",

            "risk": "Low"

        })


        # =====================================
        # HOSTNAME CHECK
        # =====================================

        hostname = socket.gethostname()

        results.append({

            "category": "System Identity",

            "finding": hostname,

            "details": "Device hostname detected successfully.",

            "risk": "Low"

        })


        # =====================================
        # IP ADDRESS CHECK
        # =====================================

        try:

            ip_address = socket.gethostbyname(hostname)

            risk = "Low"

            if ip_address.startswith("127."):

                risk = "Medium"

            results.append({

                "category": "Network",

                "finding": "Local IP Address",

                "details": f"Detected IP address: {ip_address}",

                "risk": risk

            })

        except Exception:

            results.append({

                "category": "Network",

                "finding": "IP Detection",

                "details": "Unable to determine local IP address.",

                "risk": "Medium"

            })


        # =====================================
        # DISK SPACE CHECK
        # =====================================

        try:

            total, used, free = shutil.disk_usage("/")

            usage_percentage = (used / total) * 100

            if usage_percentage > 90:

                risk = "High"

            elif usage_percentage > 80:

                risk = "Medium"

            else:

                risk = "Low"

            results.append({

                "category": "Storage",

                "finding": "Disk Usage",

                "details": f"Disk usage is {usage_percentage:.1f}%",

                "risk": risk

            })

        except Exception:

            results.append({

                "category": "Storage",

                "finding": "Disk Scan",

                "details": "Unable to analyse disk usage.",

                "risk": "Medium"

            })


        # =====================================
        # USER ACCOUNT CHECK
        # =====================================

        try:

            username = os.getlogin()

        except Exception:

            username = os.environ.get("USERNAME", "Unknown User")


        results.append({

            "category": "User Security",

            "finding": username,

            "details": "Current active device user detected.",

            "risk": "Low"

        })


        # =====================================
        # PLATFORM ARCHITECTURE
        # =====================================

        architecture = platform.machine()


        results.append({

            "category": "System Architecture",

            "finding": architecture,

            "details": "System processor architecture detected.",

            "risk": "Low"

        })


        # =====================================
        # SYSTEM RELEASE
        # =====================================

        release = platform.release()


        results.append({

            "category": "Operating System",

            "finding": "System Release",

            "details": f"Release version: {release}",

            "risk": "Low"

        })


        # =====================================
        # SCAN TIME
        # =====================================

        scan_time = datetime.now().strftime(

            "%d-%m-%Y %I:%M:%S %p"

        )


        results.append({

            "category": "Scan Information",

            "finding": "Device Scan Completed",

            "details": f"Security analysis completed at {scan_time}",

            "risk": "Low"

        })


        return results