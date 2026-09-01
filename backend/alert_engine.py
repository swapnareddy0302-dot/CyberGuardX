from datetime import datetime


class AlertEngine:

    def generate_alerts(self, iam_result, ec2_result, s3_result, sg_result):

        alerts = []

      
        # IAM Alerts
      
        for user in iam_result:

            username = user.get("name", "Unknown User")

            if not user.get("mfa_enabled"):

                alerts.append({
                    "severity": "Critical",
                    "service": "IAM",
                    "message": f"{username} has MFA disabled",
                    "time": datetime.now().strftime("%H:%M:%S")
                })

            if user.get("is_admin"):

                alerts.append({
                    "severity": "High",
                    "service": "IAM",
                    "message": f"{username} has Administrator privileges",
                    "time": datetime.now().strftime("%H:%M:%S")
                })

            if not user.get("active"):

                alerts.append({
                    "severity": "Medium",
                    "service": "IAM",
                    "message": f"{username} account is inactive",
                    "time": datetime.now().strftime("%H:%M:%S")
                })

     
        # EC2 Alerts
        
        for instance in ec2_result:

            if instance.get("risk") == "High":

                instance_id = instance.get("instance_id", "Unknown Instance")

                alerts.append({
                    "severity": "High",
                    "service": "EC2",
                    "message": f"{instance_id} is publicly accessible",
                    "time": datetime.now().strftime("%H:%M:%S")
                })

     
        # S3 Alerts
      
        for bucket in s3_result:

            if bucket.get("risk") == "High":

                bucket_name = bucket.get("bucket_name", "Unknown Bucket")

                alerts.append({
                    "severity": "Medium",
                    "service": "S3",
                    "message": f"{bucket_name} bucket requires attention",
                    "time": datetime.now().strftime("%H:%M:%S")
                })

     
        # Security Group Alerts
      
        for group in sg_result:

            if group.get("risk") == "High":

                group_name = group.get("group_name", "Unknown Security Group")

                alerts.append({
                    "severity": "Critical",
                    "service": "Security Group",
                    "message": f"{group_name} has insecure inbound rules",
                    "time": datetime.now().strftime("%H:%M:%S")
                })

        # Information Alert
       
        alerts.append({
            "severity": "Info",
            "service": "System",
            "message": "Security scan completed successfully",
            "time": datetime.now().strftime("%H:%M:%S")
        })

        return alerts