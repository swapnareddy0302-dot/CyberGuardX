# ============================================================
# CyberGuardX
# Risk Engine
# Cloud Security Risk Analysis & Scoring
# ============================================================


class RiskEngine:

    def __init__(self):
        self.score = 100


    # ========================================================
    # SAFE VALUE HELPER
    # ========================================================

    @staticmethod
    def get_value(item, *keys, default="Unknown"):

        if not isinstance(item, dict):
            return default

        for key in keys:

            value = item.get(key)

            if value is not None and str(value).strip() != "":
                return value

        return default


    # ========================================================
    # RISK LEVEL HELPER
    # ========================================================

    @staticmethod
    def get_risk(item, default="Medium"):

        if not isinstance(item, dict):
            return default

        risk = (
            item.get("risk")
            or item.get("level")
            or item.get("severity")
            or default
        )

        risk = str(risk).strip().capitalize()

        if risk not in ["High", "Medium", "Low"]:
            return default

        return risk


    # ========================================================
    # CALCULATE SECURITY SCORE
    # ========================================================

    def calculate_score(
        self,
        iam,
        ec2,
        s3,
        security_groups
    ):

        score = 100

        risks = []


        # ====================================================
        # SAFETY
        # ====================================================

        if not isinstance(iam, list):
            iam = []

        if not isinstance(ec2, list):
            ec2 = []

        if not isinstance(s3, list):
            s3 = []

        if not isinstance(security_groups, list):
            security_groups = []


        # ====================================================
        # IAM SECURITY CHECK
        # ====================================================

        for user in iam:

            if not isinstance(user, dict):
                continue


            username = self.get_value(
                user,
                "user",
                "username",
                "user_name",
                "name",
                "UserName",
                default="Unknown User"
            )


            # ------------------------------------------------
            # MFA DISABLED
            # ------------------------------------------------

            mfa = str(
                user.get("mfa", "")
            ).strip().lower()

            if mfa in [
                "disabled",
                "no",
                "false",
                "not enabled"
            ]:

                level = self.get_risk(
                    user,
                    "Medium"
                )

                risks.append({

                    "level": level,

                    "service": "IAM",

                    "title": "MFA Disabled",

                    "resource": str(username),

                    "message": (
                        f"User {username} "
                        f"does not have MFA enabled"
                    )
                })


            # ------------------------------------------------
            # ADMIN PRIVILEGE
            # ------------------------------------------------

            admin = str(
                user.get("admin", "")
            ).strip().lower()

            if admin in [
                "yes",
                "true",
                "admin"
            ]:

                risks.append({

                    "level": "Medium",

                    "service": "IAM",

                    "title": "Administrator Privileges",

                    "resource": str(username),

                    "message": (
                        f"User {username} "
                        f"has administrator privileges"
                    )
                })


            # ------------------------------------------------
            # INACTIVE USER
            # ------------------------------------------------

            status = str(
                user.get("status", "")
            ).strip().lower()

            if status == "inactive":

                risks.append({

                    "level": "Medium",

                    "service": "IAM",

                    "title": "Inactive IAM Account",

                    "resource": str(username),

                    "message": (
                        f"User {username} "
                        f"account is inactive"
                    )
                })


        # ====================================================
        # EC2 SECURITY CHECK
        # ====================================================

        for instance in ec2:

            if not isinstance(instance, dict):
                continue


            instance_name = self.get_value(

                instance,

                "name",

                "instance_name",

                "instance",

                "instance_id",

                "id",

                "InstanceId",

                "Name",

                default="Unknown EC2 Instance"
            )


            risk = self.get_risk(
                instance,
                "Medium"
            )


            if risk != "Low":

                risks.append({

                    "level": risk,

                    "service": "EC2",

                    "title": "EC2 Security Finding",

                    "resource": str(instance_name),

                    "message": (
                        f"EC2 instance "
                        f"{instance_name} "
                        f"requires security attention"
                    )
                })


        # ====================================================
        # S3 SECURITY CHECK
        # ====================================================

        for bucket in s3:

            if not isinstance(bucket, dict):
                continue


            bucket_name = self.get_value(

                bucket,

                "bucket",

                "bucket_name",

                "name",

                "bucketName",

                "Name",

                default="Unknown S3 Bucket"
            )


            risk = self.get_risk(
                bucket,
                "Medium"
            )


            if risk != "Low":

                risks.append({

                    "level": risk,

                    "service": "S3",

                    "title": "S3 Security Finding",

                    "resource": str(bucket_name),

                    "message": (
                        f"S3 bucket "
                        f"'{bucket_name}' "
                        f"requires security attention"
                    )
                })


        # ====================================================
        # SECURITY GROUP CHECK
        # ====================================================

        for sg in security_groups:

            if not isinstance(sg, dict):
                continue


            group_name = self.get_value(

                sg,

                "group",

                "group_name",

                "security_group",

                "security_group_name",

                "name",

                "GroupName",

                default="Unknown Security Group"
            )


            risk = self.get_risk(
                sg,
                "Medium"
            )


            if risk != "Low":

                risks.append({

                    "level": risk,

                    "service": "Security Group",

                    "title": "Security Group Finding",

                    "resource": str(group_name),

                    "message": (
                        f"Security Group "
                        f"{group_name} "
                        f"has potentially risky inbound rules"
                    )
                })


        # ====================================================
        # CALCULATE RISK COUNTS
        # ====================================================

        high_count = 0
        medium_count = 0
        low_count = 0


        for risk in risks:

            level = str(
                risk.get("level", "Low")
            ).strip().capitalize()


            if level == "High":

                high_count += 1

                score -= 15


            elif level == "Medium":

                medium_count += 1

                score -= 7


            else:

                low_count += 1

                score -= 2


        # ====================================================
        # PREVENT NEGATIVE SCORE
        # ====================================================

        score = max(
            0,
            min(score, 100)
        )


        # ====================================================
        # SECURITY STATUS
        # ====================================================

        if score >= 90:

            status = "Excellent"

        elif score >= 75:

            status = "Secure"

        elif score >= 50:

            status = "Needs Attention"

        else:

            status = "High Risk"


        # ====================================================
        # RETURN RESULT
        # ====================================================

        return {

            "score": score,

            "status": status,

            "risks": risks,

            "high_count": high_count,

            "medium_count": medium_count,

            "low_count": low_count

        }