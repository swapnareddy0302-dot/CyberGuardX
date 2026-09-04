# ============================================================
# CyberGuardX
# Security Group Scanner
# Demo / Development Version
# ============================================================


class SecurityGroupScanner:

    def scan(self):

        security_groups = [

            {
                "name": "WebServerSG",
                "port": "22",
                "source": "0.0.0.0/0",
                "risk": "High"
            },

            {
                "name": "ApplicationSG",
                "port": "443",
                "source": "0.0.0.0/0",
                "risk": "Low"
            },

            {
                "name": "DatabaseSG",
                "port": "3306",
                "source": "10.0.0.0/16",
                "risk": "Low"
            },

            {
                "name": "AdminSG",
                "port": "3389",
                "source": "0.0.0.0/0",
                "risk": "High"
            },

            {
                "name": "SSHAccessSG",
                "port": "22",
                "source": "192.168.1.0/24",
                "risk": "Medium"
            },

            {
                "name": "InternalSG",
                "port": "8080",
                "source": "10.0.0.0/16",
                "risk": "Low"
            },

            {
                "name": "MonitoringSG",
                "port": "9090",
                "source": "0.0.0.0/0",
                "risk": "Medium"
            },

            {
                "name": "APIGatewaySG",
                "port": "443",
                "source": "0.0.0.0/0",
                "risk": "Low"
            }

        ]

        return security_groups