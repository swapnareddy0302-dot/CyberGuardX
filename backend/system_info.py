import platform
import socket


def get_system_info():
    """Returns basic system information."""

    try:
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
    except Exception:
        ip_address = "Unable to fetch"

    info = {
        "Operating System": platform.system(),
        "OS Version": platform.version(),
        "Machine": platform.machine(),
        "Hostname": hostname,
        "Processor": platform.processor(),
        "IP Address": ip_address,
        "Python Version": platform.python_version()
    }

    return info