class RiskEngine:

    def __init__(self):
        self.score = 100


    def calculate_score(self, iam, ec2, s3, security_groups):

        score = 100
        risks = []


        # ==========================================
        # IAM SECURITY CHECK
        # ==========================================

        for user in iam:

            # MFA Disabled
            if user.get("mfa") == "Disabled":

                level = user.get("risk", "Medium")

                risks.append({
                    "level": level,
                    "service": "IAM",
                    "message": (
                        f"User {user.get('user')} "
                        f"does not have MFA enabled"
                    )
                })


            # Admin Privilege
            if user.get("admin") == "Yes":

                risks.append({
                    "level": "Medium",
                    "service": "IAM",
                    "message": (
                        f"User {user.get('user')} "
                        f"has administrator privileges"
                    )
                })


            # Inactive User
            if user.get("status") == "Inactive":

                risks.append({
                    "level": "Medium",
                    "service": "IAM",
                    "message": (
                        f"User {user.get('user')} "
                        f"account is inactive"
                    )
                })


        # ==========================================
        # EC2 SECURITY CHECK
        # ==========================================

        for instance in ec2:

            if instance.get("risk") != "Low":

                risks.append({
                    "level": instance.get("risk", "Medium"),
                    "service": "EC2",
                    "message": (
                        f"EC2 instance "
                        f"{instance.get('name')} "
                        f"requires security attention"
                    )
                })


        # ==========================================
        # S3 SECURITY CHECK
        # ==========================================

        for bucket in s3:

            if bucket.get("risk") != "Low":

                risks.append({
                    "level": bucket.get("risk", "Medium"),
                    "service": "S3",
                    "message": (
                        f"S3 bucket "
                        f"'{bucket.get('bucket')}' "
                        f"requires security attention"
                    )
                })


        # ==========================================
        # SECURITY GROUP CHECK
        # ==========================================

        for sg in security_groups:

            if sg.get("risk") != "Low":

                risks.append({
                    "level": sg.get("risk", "Medium"),
                    "service": "Security Group",
                    "message": (
                        f"Security Group "
                        f"{sg.get('group')} "
                        f"has potentially risky inbound rules"
                    )
                })


        # ==========================================
        # CALCULATE SCORE FROM FINAL RISKS
        # ==========================================

        high_count = 0
        medium_count = 0
        low_count = 0


        for risk in risks:

            if risk["level"] == "High":

                high_count += 1
                score -= 15


            elif risk["level"] == "Medium":

                medium_count += 1
                score -= 7


            elif risk["level"] == "Low":

                low_count += 1
                score -= 2


        # Prevent negative score

        score = max(score, 0)


        # ==========================================
        # OVERALL SECURITY STATUS
        # ==========================================

        if score >= 90:

            status = "Excellent"

        elif score >= 75:

            status = "Secure"

        elif score >= 50:

            status = "Needs Attention"

        else:

            status = "High Risk"


        # ==========================================
        # RETURN RESULT
        # ==========================================

        return {

            "score": score,

            "status": status,

            "risks": risks,

            "high_count": high_count,

            "medium_count": medium_count,

            "low_count": low_count

        }