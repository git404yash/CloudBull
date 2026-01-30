#!/usr/bin/env python3
"""
CloudBull – AWS Security & Misconfiguration Scanner (Single-file)
Audits AWS accounts for common misconfigurations in S3, IAM, Security Groups, EC2, and ECS.
"""

import boto3
from tabulate import tabulate

# -----------------------------
# Utility function to print findings
# -----------------------------
def print_findings(title, findings):
    if not findings:
        print(f"[+] {title}: No issues found\n")
        return
    print(f"[!] {title}")
    print(tabulate(findings, headers="keys"))
    print()

# -----------------------------
# S3 Checks
# -----------------------------
def check_s3():
    s3 = boto3.client("s3")
    findings = []

    for bucket in s3.list_buckets()["Buckets"]:
        name = bucket["Name"]
        try:
            pab = s3.get_public_access_block(Bucket=name)
            if not all(pab["PublicAccessBlockConfiguration"].values()):
                findings.append({
                    "Resource": name,
                    "Issue": "Public access not fully blocked",
                    "Remediation": "Enable S3 Block Public Access"
                })
        except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
            findings.append({
                "Resource": name,
                "Issue": "No public access block configured",
                "Remediation": "Enable S3 Block Public Access"
            })
    return findings

# -----------------------------
# Security Group Checks
# -----------------------------
RISKY_PORTS = [22, 3389]

def check_security_groups():
    ec2 = boto3.client("ec2")
    findings = []

    for sg in ec2.describe_security_groups()["SecurityGroups"]:
        for perm in sg.get("IpPermissions", []):
            from_port = perm.get("FromPort")
            for ip in perm.get("IpRanges", []):
                if ip.get("CidrIp") == "0.0.0.0/0" and from_port in RISKY_PORTS:
                    findings.append({
                        "Resource": sg["GroupId"],
                        "Issue": f"Port {from_port} open to world",
                        "Remediation": "Restrict ingress to trusted IPs"
                    })
    return findings

# -----------------------------
# IAM Checks
# -----------------------------
def check_iam():
    iam = boto3.client("iam")
    findings = []

    for role in iam.list_roles()["Roles"]:
        role_name = role["RoleName"]
        policies = iam.list_role_policies(RoleName=role_name)["PolicyNames"]

        for policy in policies:
            doc = iam.get_role_policy(RoleName=role_name, PolicyName=policy)["PolicyDocument"]
            statements = doc.get("Statement", [])
            if not isinstance(statements, list):
                statements = [statements]
            for stmt in statements:
                if stmt.get("Action") == "*" and stmt.get("Resource") == "*":
                    findings.append({
                        "Resource": role_name,
                        "Issue": "Overly permissive IAM policy",
                        "Remediation": "Apply least-privilege permissions"
                    })
    return findings

# -----------------------------
# EC2 Checks
# -----------------------------
def check_ec2():
    ec2 = boto3.client("ec2")
    findings = []

    for r in ec2.describe_instances()["Reservations"]:
        for i in r["Instances"]:
            instance_id = i["InstanceId"]
            if i.get("PublicIpAddress"):
                findings.append({
                    "Resource": instance_id,
                    "Issue": "EC2 instance has public IP",
                    "Remediation": "Remove public IP or restrict access"
                })
    return findings

# -----------------------------
# ECS Checks (basic)
# -----------------------------
def check_ecs():
    ecs = boto3.client("ecs")
    findings = []

    clusters = ecs.list_clusters()["clusterArns"]
    for cluster in clusters:
        services = ecs.list_services(cluster=cluster)["serviceArns"]
        for svc in services:
            desc = ecs.describe_services(cluster=cluster, services=[svc])["services"][0]
            if desc.get("launchType") == "FARGATE":
                findings.append({
                    "Resource": desc["serviceName"],
                    "Issue": "Public-facing ECS service possible",
                    "Remediation": "Review ALB exposure and task role permissions"
                })
    return findings

# -----------------------------
# Main Function
# -----------------------------
def main():
    print("\n=== CloudBull AWS Security Scanner ===\n")
    print_findings("S3 Bucket Checks", check_s3())
    print_findings("IAM Policy Checks", check_iam())
    print_findings("Security Group Checks", check_security_groups())
    print_findings("EC2 Exposure Checks", check_ec2())
    print_findings("ECS Exposure Checks", check_ecs())

# -----------------------------
# Entry Point
# -----------------------------
if __name__ == "__main__":
    main()
