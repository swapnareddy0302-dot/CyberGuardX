# ============================================================
# CyberGuardX
# S3 Security Scanner
# Demo / Development Version
# ============================================================


class S3Scanner:

    def scan(self):

        buckets = [

            {
                "name": "company-production-data",
                "region": "ap-south-1",
                "public_access": True,
                "encryption": False,
                "versioning": True,
                "risk": "High"
            },

            {
                "name": "company-backups",
                "region": "ap-south-1",
                "public_access": False,
                "encryption": True,
                "versioning": True,
                "risk": "Low"
            },

            {
                "name": "application-assets",
                "region": "ap-south-1",
                "public_access": False,
                "encryption": True,
                "versioning": True,
                "risk": "Low"
            },

            {
                "name": "development-data",
                "region": "ap-south-1",
                "public_access": True,
                "encryption": True,
                "versioning": False,
                "risk": "Medium"
            },

            {
                "name": "security-logs",
                "region": "ap-south-1",
                "public_access": False,
                "encryption": True,
                "versioning": True,
                "risk": "Low"
            },

            {
                "name": "analytics-data",
                "region": "ap-south-1",
                "public_access": False,
                "encryption": True,
                "versioning": False,
                "risk": "Low"
            },

            {
                "name": "temporary-storage",
                "region": "ap-south-1",
                "public_access": True,
                "encryption": False,
                "versioning": False,
                "risk": "High"
            },

            {
                "name": "website-assets",
                "region": "ap-south-1",
                "public_access": False,
                "encryption": True,
                "versioning": True,
                "risk": "Low"
            }

        ]

        return buckets