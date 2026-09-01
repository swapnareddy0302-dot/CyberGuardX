class SecurityAdvisor:

    def generate_advice(self, iam_result, ec2_result, s3_result, sg_result):

        recommendations = []

     
        # IAM Security Checks
     
        for user in iam_result:

            if user.get("is_admin") and not user.get("mfa_enabled"):

                recommendations.append({

                    "severity": "Critical",
                    "status": "Security Issue Detected",
                    "priority": "Critical",
                    "issue": f"Admin user {user.get('name')} has MFA disabled",
                    "recommendation": "Enable Multi-Factor Authentication for privileged IAM accounts."

                })

            elif not user.get("active"):

                recommendations.append({

                    "severity": "Medium",
                    "status": "Security Issue Detected",
                    "priority": "Medium",
                    "issue": f"User {user.get('name')} account is inactive",
                    "recommendation": "Review or remove inactive IAM users."

                })

     
        # EC2 Security Checks
       
        for instance in ec2_result:

            if instance.get("risk") == "High":

                recommendations.append({

                    "severity": "High",
                    "status": "Security Issue Detected",
                    "priority": "High",
                    "issue": f"EC2 Instance {instance.get('instance_id')} is publicly accessible",
                    "recommendation": "Restrict public access and review security groups."

                })

       
        # S3 Security Checks

        for bucket in s3_result:

            if bucket.get("risk") == "High":

                recommendations.append({

                    "severity": "High",
                    "status": "Security Issue Detected",
                    "priority": "High",
                    "issue": f"S3 Bucket {bucket.get('bucket_name')} is publicly accessible",
                    "recommendation": "Block public access and enable bucket encryption."

                })

    
        # Security Group Checks
    
        for group in sg_result:

            if group.get("risk") == "High":

                recommendations.append({

                    "severity": "Critical",
                    "status": "Security Issue Detected",
                    "priority": "Critical",
                    "issue": f"Security Group {group.get('group_name')} allows risky access",
                    "recommendation": "Remove open inbound rules and restrict source IP addresses."

                })

        if not recommendations:

            recommendations.append({

                "severity": "Info",
                "status": "Secure",
                "priority": "Low",
                "issue": "No major security issues detected.",
                "recommendation": "Continue following AWS security best practices."

            })

        return recommendations