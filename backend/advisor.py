# ============================================================
# CyberGuardX
# Security Advisor
# Cloud Security Recommendations
# ============================================================


class SecurityAdvisor:

    def __init__(self):
        self.recommendations = []


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
    # ADD RECOMMENDATION
    # ========================================================

    def add_recommendation(
        self,
        service,
        title,
        resource,
        message,
        priority="Medium"
    ):

        self.recommendations.append({

            "service": service,

            "title": title,

            "resource": resource,

            "message": message,

            "priority": priority

        })


    # ========================================================
    # GENERATE SECURITY ADVICE
    # ========================================================

    def generate_advice(
        self,
        iam,
        ec2,
        s3,
        security_groups
    ):

        self.recommendations = []


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
        # IAM SECURITY
        # ====================================================

        for user in iam:

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
            # MFA
            # ------------------------------------------------

            mfa_enabled = user.get("mfa_enabled")


            if mfa_enabled is False:

                self.add_recommendation(

                    service="IAM",

                    title="Enable Multi-Factor Authentication",

                    resource=username,

                    message=(
                        f"Enable MFA for IAM user "
                        f"'{username}' to provide an additional "
                        f"authentication layer."
                    ),

                    priority="High"
                )


            # ------------------------------------------------
            # ADMIN PRIVILEGES
            # ------------------------------------------------

            is_admin = user.get("is_admin")


            if is_admin is True:

                self.add_recommendation(

                    service="IAM",

                    title="Review Administrator Privileges",

                    resource=username,

                    message=(
                        f"Review administrator permissions for "
                        f"'{username}' and apply the principle "
                        f"of least privilege."
                    ),

                    priority="High"
                )


            # ------------------------------------------------
            # INACTIVE USER
            # ------------------------------------------------

            status = str(
                user.get("status", "")
            ).strip().lower()


            if status == "inactive":

                self.add_recommendation(

                    service="IAM",

                    title="Remove or Disable Inactive Account",

                    resource=username,

                    message=(
                        f"Review inactive IAM account "
                        f"'{username}' and disable or remove "
                        f"it if it is no longer required."
                    ),

                    priority="Medium"
                )


        # ====================================================
        # EC2 SECURITY
        # ====================================================

        for instance in ec2:

            if not isinstance(instance, dict):
                continue


            instance_name = self.get_value(

                instance,

                "name",

                "instance_name",

                "instance",

                "id",

                "instance_id",

                default="Unknown EC2 Instance"
            )


            risk = str(
                instance.get("risk", "Low")
            ).strip().capitalize()


            public_ip = instance.get("public_ip")


            # ------------------------------------------------
            # HIGH-RISK EC2
            # ------------------------------------------------

            if risk == "High":

                self.add_recommendation(

                    service="EC2",

                    title="Review EC2 Instance Exposure",

                    resource=instance_name,

                    message=(
                        f"EC2 instance '{instance_name}' "
                        f"is classified as high risk. Review "
                        f"network exposure, security groups and "
                        f"access permissions."
                    ),

                    priority="High"
                )


            # ------------------------------------------------
            # PUBLIC IP
            # ------------------------------------------------

            if public_ip:

                self.add_recommendation(

                    service="EC2",

                    title="Review Public IP Exposure",

                    resource=instance_name,

                    message=(
                        f"EC2 instance '{instance_name}' "
                        f"has a public IP address "
                        f"({public_ip}). Verify that direct "
                        f"Internet exposure is required."
                    ),

                    priority="Medium"
                )


        # ====================================================
        # S3 SECURITY
        # ====================================================

        for bucket in s3:

            if not isinstance(bucket, dict):
                continue


            bucket_name = self.get_value(

                bucket,

                "name",

                "bucket",

                "bucket_name",

                "bucketName",

                default="Unknown S3 Bucket"
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

            versioning = bucket.get(
                "versioning"
            )


            # ------------------------------------------------
            # HIGH-RISK BUCKET
            # ------------------------------------------------

            if risk == "High":

                self.add_recommendation(

                    service="S3",

                    title="Restrict Public Bucket Access",

                    resource=bucket_name,

                    message=(
                        f"S3 bucket '{bucket_name}' "
                        f"is classified as high risk. "
                        f"Review public access settings and "
                        f"restrict unnecessary Internet exposure."
                    ),

                    priority="High"
                )


            # ------------------------------------------------
            # PUBLIC ACCESS
            # ------------------------------------------------

            if public_access is True:

                self.add_recommendation(

                    service="S3",

                    title="Disable Unnecessary Public Access",

                    resource=bucket_name,

                    message=(
                        f"S3 bucket '{bucket_name}' "
                        f"allows public access. Disable public "
                        f"access unless it is explicitly required."
                    ),

                    priority="High"
                )


            # ------------------------------------------------
            # ENCRYPTION
            # ------------------------------------------------

            if encryption is False:

                self.add_recommendation(

                    service="S3",

                    title="Enable S3 Encryption",

                    resource=bucket_name,

                    message=(
                        f"Enable encryption for S3 bucket "
                        f"'{bucket_name}' to protect stored data."
                    ),

                    priority="High"
                )


            # ------------------------------------------------
            # VERSIONING
            # ------------------------------------------------

            if versioning is False:

                self.add_recommendation(

                    service="S3",

                    title="Enable Bucket Versioning",

                    resource=bucket_name,

                    message=(
                        f"Enable versioning for S3 bucket "
                        f"'{bucket_name}' to improve data recovery "
                        f"and protection against accidental deletion."
                    ),

                    priority="Medium"
                )


        # ====================================================
        # SECURITY GROUPS
        # ====================================================

        for sg in security_groups:

            if not isinstance(sg, dict):
                continue


            group_name = self.get_value(

                sg,

                "name",

                "group",

                "group_name",

                "security_group",

                "security_group_name",

                default="Unknown Security Group"
            )


            port = self.get_value(

                sg,

                "port",

                default="Unknown Port"
            )


            source = self.get_value(

                sg,

                "source",

                default="Unknown Source"
            )


            risk = str(
                sg.get("risk", "Low")
            ).strip().capitalize()


            # ------------------------------------------------
            # HIGH-RISK SECURITY GROUP
            # ------------------------------------------------

            if risk == "High":

                self.add_recommendation(

                    service="Security Group",

                    title="Restrict Open Inbound Rule",

                    resource=group_name,

                    message=(
                        f"Security Group '{group_name}' "
                        f"allows inbound traffic on port "
                        f"{port} from {source}. Restrict the "
                        f"source range to trusted networks."
                    ),

                    priority="High"
                )


            # ------------------------------------------------
            # MEDIUM-RISK SECURITY GROUP
            # ------------------------------------------------

            elif risk == "Medium":

                self.add_recommendation(

                    service="Security Group",

                    title="Review Inbound Network Rule",

                    resource=group_name,

                    message=(
                        f"Review Security Group '{group_name}' "
                        f"and restrict port {port} access from "
                        f"{source} where possible."
                    ),

                    priority="Medium"
                )


        # ====================================================
        # GENERAL SECURITY RECOMMENDATION
        # ====================================================

        if not self.recommendations:

            self.add_recommendation(

                service="CyberGuardX",

                title="Security Posture Looks Good",

                resource="Cloud Environment",

                message=(
                    "No significant security recommendations "
                    "were generated from the current cloud scan."
                ),

                priority="Low"
            )


        # ====================================================
        # RETURN
        # ====================================================

        return self.recommendations