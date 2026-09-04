# ============================================================
# CyberGuardX
# Security Alert Engine
# Cloud Security Monitoring
# ============================================================

from datetime import datetime


class AlertEngine:

    # ========================================================
    # TIME HELPER
    # ========================================================

    @staticmethod
    def current_time():
        return datetime.now().strftime("%H:%M:%S")


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
    # ADD ALERT
    # ========================================================

    @staticmethod
    def add_alert(
        alerts,
        severity,
        service,
        message
    ):

        alerts.append({

            "severity": severity,

            "service": service,

            "message": message,

            "time": AlertEngine.current_time()

        })


    # ========================================================
    # GENERATE ALERTS
    # ========================================================

    def generate_alerts(
        self,
        iam_result,
        ec2_result,
        s3_result,
        sg_result
    ):

        alerts = []


        # ====================================================
        # SAFETY
        # ====================================================

        if not isinstance(iam_result, list):
            iam_result = []

        if not isinstance(ec2_result, list):
            ec2_result = []

        if not isinstance(s3_result, list):
            s3_result = []

        if not isinstance(sg_result, list):
            sg_result = []


        # ====================================================
        # IAM SECURITY ALERTS
        # ====================================================

        for user in iam_result:

            if not isinstance(user, dict):
                continue


            username = self.get_value(

                user,

                "name",
                "username",
                "user",
                "user_name",

                default="Unknown User"
            )


            # ------------------------------------------------
            # MFA DISABLED
            # ------------------------------------------------

            if user.get("mfa_enabled") is False:

                self.add_alert(

                    alerts,

                    "Critical",

                    "IAM",

                    f"{username} has MFA disabled"
                )


            # ------------------------------------------------
            # ADMINISTRATOR PRIVILEGES
            # ------------------------------------------------

            if user.get("is_admin") is True:

                self.add_alert(

                    alerts,

                    "High",

                    "IAM",

                    f"{username} has Administrator privileges"
                )


            # ------------------------------------------------
            # INACTIVE ACCOUNT
            # ------------------------------------------------

            status = str(
                user.get("status", "")
            ).strip().lower()


            if status == "inactive":

                self.add_alert(

                    alerts,

                    "Medium",

                    "IAM",

                    f"{username} account is inactive"
                )


        # ====================================================
        # EC2 SECURITY ALERTS
        # ====================================================

        for instance in ec2_result:

            if not isinstance(instance, dict):
                continue


            instance_name = self.get_value(

                instance,

                "name",
                "instance_name",
                "instance",
                "instance_id",
                "id",

                default="Unknown Instance"
            )


            risk = str(
                instance.get("risk", "Low")
            ).strip().capitalize()


            public_ip = instance.get("public_ip")


            # ------------------------------------------------
            # HIGH-RISK INSTANCE
            # ------------------------------------------------

            if risk == "High":

                if public_ip:

                    message = (
                        f"{instance_name} is publicly "
                        f"accessible at {public_ip}"
                    )

                else:

                    message = (
                        f"{instance_name} is classified "
                        f"as high risk"
                    )


                self.add_alert(

                    alerts,

                    "High",

                    "EC2",

                    message
                )


            # ------------------------------------------------
            # PUBLIC IP
            # ------------------------------------------------

            elif public_ip:

                self.add_alert(

                    alerts,

                    "Medium",

                    "EC2",

                    f"{instance_name} has public IP "
                    f"{public_ip}"
                )


        # ====================================================
        # S3 SECURITY ALERTS
        # ====================================================

        for bucket in s3_result:

            if not isinstance(bucket, dict):
                continue


            bucket_name = self.get_value(

                bucket,

                "name",
                "bucket",
                "bucket_name",
                "bucketName",

                default="Unknown Bucket"
            )


            risk = str(
                bucket.get("risk", "Low")
            ).strip().capitalize()


            public_access = bucket.get(
                "public_access"
            )

            encryption = bucket.get(
                "encryption"
            )


            # ------------------------------------------------
            # HIGH-RISK BUCKET
            # ------------------------------------------------

            if risk == "High":

                self.add_alert(

                    alerts,

                    "High",

                    "S3",

                    f"{bucket_name} bucket requires "
                    f"immediate security attention"
                )


            # ------------------------------------------------
            # PUBLIC ACCESS
            # ------------------------------------------------

            if public_access is True:

                self.add_alert(

                    alerts,

                    "High",

                    "S3",

                    f"{bucket_name} allows public access"
                )


            # ------------------------------------------------
            # ENCRYPTION DISABLED
            # ------------------------------------------------

            if encryption is False:

                self.add_alert(

                    alerts,

                    "Medium",

                    "S3",

                    f"{bucket_name} does not have encryption enabled"
                )


        # ====================================================
        # SECURITY GROUP ALERTS
        # ====================================================

        for group in sg_result:

            if not isinstance(group, dict):
                continue


            group_name = self.get_value(

                group,

                "name",
                "group",
                "group_name",
                "security_group",
                "security_group_name",

                default="Unknown Security Group"
            )


            port = self.get_value(

                group,

                "port",

                default="Unknown"
            )


            source = self.get_value(

                group,

                "source",

                default="Unknown"
            )


            risk = str(
                group.get("risk", "Low")
            ).strip().capitalize()


            # ------------------------------------------------
            # HIGH-RISK SECURITY GROUP
            # ------------------------------------------------

            if risk == "High":

                self.add_alert(

                    alerts,

                    "Critical",

                    "Security Group",

                    f"{group_name} has insecure inbound "
                    f"rules on port {port} from {source}"
                )


            # ------------------------------------------------
            # MEDIUM-RISK SECURITY GROUP
            # ------------------------------------------------

            elif risk == "Medium":

                self.add_alert(

                    alerts,

                    "Medium",

                    "Security Group",

                    f"{group_name} has a potentially risky "
                    f"inbound rule on port {port} from {source}"
                )


        # ====================================================
        # SCAN COMPLETION ALERT
        # ====================================================

        self.add_alert(

            alerts,

            "Info",

            "System",

            "Cloud security scan completed successfully"
        )


        # ====================================================
        # RETURN ALERTS
        # ====================================================

        return alerts