from backend.data.users import users


class IAMScanner:

    def __init__(self):
        print("IAM Scanner Initialized")

    def scan(self):

        print("Scanning IAM...")

        total_users = len(users)

        mfa_enabled = 0
        admin_users = 0
        inactive_users = 0

        for user in users:

            if user["mfa_enabled"]:
                mfa_enabled += 1

            if user["is_admin"]:
                admin_users += 1

            if not user["is_active"]:
                inactive_users += 1

        security_score = int((mfa_enabled / total_users) * 100)

        results = {
            "Total Users": total_users,
            "MFA Enabled": mfa_enabled,
            "Admin Users": admin_users,
            "Inactive Users": inactive_users,
            "Security Score": security_score
        }

        return results

       