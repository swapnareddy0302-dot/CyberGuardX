import platform
import socket

def get_system_info():

    return {

        "Operating System": platform.system(),

        "Python Version": platform.python_version(),

        "Hostname": socket.gethostname(),

        "Platform": platform.platform()

    }