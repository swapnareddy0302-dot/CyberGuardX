import random


class IAMScanner:

    def scan(self):

        users = [

            {
                "name": "admin-user",
                "mfa_enabled": False,
                "is_admin": True,
                "status": "Active",
                "risk": "High"
            },

            {
                "name": "developer-team",
                "mfa_enabled": True,
                "is_admin": False,
                "status": "Active",
                "risk": "Low"
            },

            {
                "name": "database-admin",
                "mfa_enabled": False,
                "is_admin": True,
                "status": "Active",
                "risk": "High"
            },

            {
                "name": "cloud-engineer",
                "mfa_enabled": True,
                "is_admin": False,
                "status": "Active",
                "risk": "Low"
            },

            {
                "name": "security-auditor",
                "mfa_enabled": True,
                "is_admin": False,
                "status": "Active",
                "risk": "Low"
            },

            {
                "name": "backup-service",
                "mfa_enabled": False,
                "is_admin": False,
                "status": "Inactive",
                "risk": "Medium"
            },

            {
                "name": "temporary-user",
                "mfa_enabled": False,
                "is_admin": False,
                "status": "Inactive",
                "risk": "Medium"
            },

            {
                "name": "operations-team",
                "mfa_enabled": True,
                "is_admin": False,
                "status": "Active",
                "risk": "Low"
            }

        ]

        count = random.randint(4, 7)

        return random.sample(users, count)