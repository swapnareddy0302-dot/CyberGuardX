import random


class S3Scanner:

    def scan(self):

        buckets = [

            {
                "name": "company-backup",
                "public_access": False,
                "encryption": True,
                "risk": "Low"
            },

            {
                "name": "website-assets",
                "public_access": True,
                "encryption": False,
                "risk": "High"
            },

            {
                "name": "application-logs",
                "public_access": False,
                "encryption": False,
                "risk": "Medium"
            },

            {
                "name": "customer-data",
                "public_access": False,
                "encryption": True,
                "risk": "Low"
            },

            {
                "name": "development-files",
                "public_access": True,
                "encryption": False,
                "risk": "High"
            },

            {
                "name": "archive-storage",
                "public_access": False,
                "encryption": True,
                "risk": "Low"
            },

            {
                "name": "media-assets",
                "public_access": True,
                "encryption": True,
                "risk": "Medium"
            },

            {
                "name": "audit-logs",
                "public_access": False,
                "encryption": True,
                "risk": "Low"
            }

        ]

        count = random.randint(4, 7)

        return random.sample(buckets, count)