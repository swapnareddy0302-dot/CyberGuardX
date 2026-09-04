class EC2Scanner:

    def scan(self):

        return [

            {
                "id": "i-0a1b2c3d4e5f",
                "name": "Web-Server-01",
                "state": "Running",
                "public_ip": "18.210.45.12",
                "risk": "High"
            },

            {
                "id": "i-1b2c3d4e5f6a",
                "name": "Application-Server",
                "state": "Running",
                "public_ip": None,
                "risk": "Low"
            },

            {
                "id": "i-2c3d4e5f6a7b",
                "name": "Database-Server",
                "state": "Running",
                "public_ip": None,
                "risk": "Low"
            },

            {
                "id": "i-3d4e5f6a7b8c",
                "name": "Test-Server",
                "state": "Stopped",
                "public_ip": "13.234.82.45",
                "risk": "Medium"
            },

            {
                "id": "i-4e5f6a7b8c9d",
                "name": "Analytics-Server",
                "state": "Running",
                "public_ip": None,
                "risk": "Low"
            },

            {
                "id": "i-5f6a7b8c9d0e",
                "name": "Dev-Server",
                "state": "Running",
                "public_ip": "3.110.145.78",
                "risk": "High"
            },

            {
                "id": "i-6a7b8c9d0e1f",
                "name": "Backup-Server",
                "state": "Stopped",
                "public_ip": None,
                "risk": "Low"
            },

            {
                "id": "i-7b8c9d0e1f2a",
                "name": "Monitoring-Server",
                "state": "Running",
                "public_ip": None,
                "risk": "Low"
            }

        ]