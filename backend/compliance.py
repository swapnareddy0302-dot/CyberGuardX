class ComplianceEngine:

    def generate_report(self, iam_result, ec2_result, s3_result, sg_result):

        report = []

     
        # IAM Best Practices
       
        total_users = len(iam_result)

        compliant_users = sum(
            1 for user in iam_result
            if user.get("mfa_enabled") and not user.get("is_admin")
        )

        iam_score = (
            round((compliant_users / total_users) * 100)
            if total_users > 0 else 100
        )

        report.append({
            "framework": "IAM Best Practices",
            "score": iam_score,
            "status": (
                "Excellent" if iam_score >= 90 else
                "Good" if iam_score >= 70 else
                "Needs Improvement"
            )
        })

        # EC2 Security
       
        total_instances = len(ec2_result)

        secure_instances = sum(
            1 for instance in ec2_result
            if instance.get("risk") != "High"
        )

        ec2_score = (
            round((secure_instances / total_instances) * 100)
            if total_instances > 0 else 100
        )

        report.append({
            "framework": "EC2 Security",
            "score": ec2_score,
            "status": (
                "Excellent" if ec2_score >= 90 else
                "Good" if ec2_score >= 70 else
                "Needs Improvement"
            )
        })

        # S3 Security
       
        total_buckets = len(s3_result)

        secure_buckets = sum(
            1 for bucket in s3_result
            if bucket.get("risk") != "High"
        )

        s3_score = (
            round((secure_buckets / total_buckets) * 100)
            if total_buckets > 0 else 100
        )

        report.append({
            "framework": "S3 Security",
            "score": s3_score,
            "status": (
                "Excellent" if s3_score >= 90 else
                "Good" if s3_score >= 70 else
                "Needs Improvement"
            )
        })

     
        # Security Groups
       
        total_groups = len(sg_result)

        secure_groups = sum(
            1 for group in sg_result
            if group.get("risk") != "High"
        )

        sg_score = (
            round((secure_groups / total_groups) * 100)
            if total_groups > 0 else 100
        )

        report.append({
            "framework": "Security Groups",
            "score": sg_score,
            "status": (
                "Excellent" if sg_score >= 90 else
                "Good" if sg_score >= 70 else
                "Needs Improvement"
            )
        })

        return report