import boto3
import argparse

def get_enabled_regions():
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    response = ec2_client.describe_regions(AllRegions=False)
    return [region["RegionName"] for region in response["Regions"]]

def parse_arguments():
    parser = argparse.ArgumentParser(description="Automated Cloud Security Compliance Scanner")
    parser.add_argument("--region", default="us-east-1", help="Target AWS region or 'all' for multi-region scan")
    parser.add_argument("--profile", default=None, help="AWS CLI profile to use")
    return parser.parse_args()

from checks.iam import (key_creation_date, list_iam_users, has_mfa_enabled, has_console_access, list_access_keys, has_admin_access, get_last_key_usage, active_key_count, inline_policy_count,
get_account_summary, root_mfa_enabled, root_access_keys_present, get_password_policy, minimum_length, require_symbols, require_numbers, require_uppercase, require_lowercase, max_password_age,
days_since_password_use)
from checks.s3 import (list_buckets, is_bucket_public, is_versioning_enabled, is_encryption_enabled, is_logging_enabled, has_lifecycle_rules, is_bucket_policy_public, is_bucket_acl_public)
from checks.ec2 import (list_security_groups, is_sensitive_port_public)
from checks.rds import list_rds_instances, is_rds_publicly_accessible
from checks.cloudtrail import check_cloudtrail_status

from reporter import save_scan_report
from datetime import datetime, timezone
from colorama import init, Fore, Style
init(autoreset=True)
from reporter import save_scan_report, print_risk_table

def main():
    print("\n=================================")
    print("Cloud Security Scanner v0.1")
    print("=================================")
    print("\nInitializing...")

    args = parse_arguments()

    if args.region.lower() == "all":
        target_regions = get_enabled_regions()
        print(f"[INFO] Multi-region scan intitiated across regions: {target_regions}")
    else:
        target_regions = [args.region]

    #Results Scanner
    scan_results = {
            "iam_users": [],
            "root_account": {},
            "password_policy": {},
            "s3_buckets": [],
            "security_groups": [],
            "rds_instances": [],
            "cloudtrail": {}
        }

    #tracking counters for summary
    total_passes = 0
    critical_fails = 0
    high_fails = 0
    medium_fails = 0
    low_fails = 0
    total_info = 0

    sts_client = boto3.client('sts')
    identity = sts_client.get_caller_identity()

    print("Connected to AWS successfully!")
    print(f"Account ID: {identity['Account']}")
    print(f"ARN: {identity['Arn']}")
    print(f"User ID: {identity['UserId']}")
    print("Setup complete!")

# IAM User Scanning
    print("\nScanning IAM users...")

    users = list_iam_users()

    print(f"Found {len(users)} IAM user(s).\n")

    for user in users:
        if has_console_access(user["UserName"]):
            print(f"[{Fore.GREEN}PASS{Style.RESET_ALL}] {user['UserName']}: Console access is enabled")
            total_passes += 1
            if has_mfa_enabled(user["UserName"]):
                print(f"[{Fore.GREEN}PASS{Style.RESET_ALL}] {user['UserName']}: MFA is enabled")
                total_passes += 1
            else:
                print(f"[{Fore.RED}FAIL{Style.RESET_ALL}] {user['UserName']}: MFA is not enabled")
                medium_fails += 1
        else:
            print(f"[{Fore.BLUE}INFO{Style.RESET_ALL}] {user['UserName']}: No console access (MFA not applicable)")

        access_keys = list_access_keys(user["UserName"])
        for key in access_keys:
            print(
                f"[{Fore.BLUE}INFO{Style.RESET_ALL}] {user['UserName']}: "
                f"Access Key {key['AccessKeyId']} is {key['Status']}"
            )

            key_date = key_creation_date(key["CreateDate"])
            if key_date > 90:
                status = f"[{Fore.RED}FAIL{Style.RESET_ALL}]"
                medium_fails += 1
                message = "older than 90 days"
            else:
                status = f"[{Fore.GREEN}PASS{Style.RESET_ALL}]"
                total_passes += 1
                message = "less than 90 days"
            print(
                f"[{status}] Access Key {key['AccessKeyId']} for user "
                f"{user['UserName']} is {message} ({key_date} day(s) old)")

            last_used = get_last_key_usage(key["AccessKeyId"])
            if last_used is None:
                status = f"[{Fore.RED}FAIL{Style.RESET_ALL}]"
                medium_fails += 1
                message = "Access key has never been used"
            else:
                current_time = datetime.now(timezone.utc)
                difference = current_time - last_used
                days_since_used = difference.days
                if days_since_used > 90:
                    status = f"[{Fore.RED}FAIL{Style.RESET_ALL}]"
                    medium_fails += 1
                    message = f"Access key has not been used in {days_since_used} days"
                else:
                    status = f"[{Fore.GREEN}PASS{Style.RESET_ALL}]"
                    total_passes += 1
                    message = f"Access key was used {days_since_used} days ago"
            print(f"[{status}] {message}")

            active_keys = active_key_count(access_keys)
            for key in access_keys:
                if active_keys > 1:
                    status = f"[{Fore.RED}FAIL{Style.RESET_ALL}]"
                    medium_fails += 1
                    message = f"User has {active_keys} active access key"
                else:
                    status = f"[{Fore.GREEN}PASS{Style.RESET_ALL}]"
                    total_passes += 1
                    message = f"User has {active_keys} active access key"
                print(f"[{status}] {message}")

            inline_policy = inline_policy_count(user["UserName"])
            if inline_policy > 0:
                status = f"[{Fore.RED}FAIL{Style.RESET_ALL}]"
                medium_fails += 1
                message = f"User has {inline_policy} inline polic"
                if inline_policy == 1:
                    message += "y"
                else:
                    message += "ies"
            else:
                status = f"[{Fore.GREEN}PASS{Style.RESET_ALL}]"
                total_passes += 1
                message = "User has no inline policies"
            print(f"[{status}] {message}")

        has_admin = has_admin_access(user["UserName"])
        if has_admin:
            status = f"[{Fore.RED}FAIL{Style.RESET_ALL}]"
            medium_fails += 1
            message = "User has administrative privileges"
        else:
            status = f"[{Fore.GREEN}PASS{Style.RESET_ALL}]"
            total_passes += 1
            message = "User does not have administrative privileges"
        print(f"[{status}] {message}\n")

        scan_results["iam_users"].append({
                    "username": user["UserName"],
                    "console_access": has_console_access(user["UserName"]),
                    "mfa_enabled": has_mfa_enabled(user["UserName"]),
                    "active_access_keys": active_key_count(access_keys),
                    "inline_policies": inline_policy_count(user["UserName"]),
                    "admin_access": has_admin_access(user["UserName"])
                })
        
        #Root User Checks
        print("=== Root Account Checks ===\n")
        root_mfa = root_mfa_enabled()

        root_keys = root_access_keys_present()
        if root_keys:
            status = f"[{Fore.RED}FAIL{Style.RESET_ALL}]"
            high_fails += 1
            message = "Root access keys are present"
        else:
            status = f"[{Fore.GREEN}PASS{Style.RESET_ALL}]"
            total_passes += 1
            message = "No root access keys are present"
        print(f"[{status}] {message}")

        root_mfa = root_mfa_enabled()
        if root_mfa:
            status = f"[{Fore.GREEN}PASS{Style.RESET_ALL}]"
            total_passes += 1
            message = "Root user has mfa enabled\n"
        else:
            status = f"[{Fore.RED}FAIL{Style.RESET_ALL}]"
            high_fails += 1
            message = "Root user has no mfa enabled\n"
        print(f"[{status}] {message}")

        scan_results["root_account"] = {
            "root_access_keys_present": root_keys,
            "root_mfa_enabled": root_mfa
        }

        #Password Check
        print("=== Password Policy ===\n")
        password_policy = get_password_policy()

        minimum_length_value = minimum_length()
        if minimum_length_value is None:
            print(f"[{Fore.RED}FAIL{Style.RESET_ALL}] No account password policy exists")
            high_fails += 1
        elif minimum_length_value >= 14:
            print(f"[{Fore.GREEN}PASS{Style.RESET_ALL}] Minimum password length is {minimum_length_value}")
            total_passes += 1
        else:
            print(f"[{Fore.RED}FAIL{Style.RESET_ALL}] Minimum password length is only {minimum_length_value}; "
                  f"recommended minimum is 14")
            high_fails += 1

        symbols_required = require_symbols()
        if symbols_required is None:
            print(f"[{Fore.RED}FAIL{Style.RESET_ALL}] No account password policy exists")
            low_fails += 1
        elif symbols_required:
            print(f"[{Fore.GREEN}PASS{Style.RESET_ALL}] Passwords require a symbol")
            total_passes += 1
        else:
            print(f"[{Fore.RED}FAIL{Style.RESET_ALL}] Passwords do not require symbols")
            low_fails += 1

        numbers_required = require_numbers()
        if numbers_required is None:
            print(f"[{Fore.RED}FAIL{Style.RESET_ALL}] No account password policy exists")
            low_fails += 1
        elif numbers_required:
            print(f"[{Fore.GREEN}PASS{Style.RESET_ALL}] Passwords require a number")
            total_passes += 1
        else:
            print(f"[{Fore.RED}FAIL{Style.RESET_ALL}] Passwords do not require numbers")
            low_fails += 1

        uppercase_requires = require_uppercase()
        if uppercase_requires is None:
            print(f"[{Fore.RED}FAIL{Style.RESET_ALL}] No account password policy exists")
            low_fails += 1
        elif uppercase_requires:
            print(f"[{Fore.GREEN}PASS{Style.RESET_ALL}] Passwords require an uppercase character")
            total_passes += 1
        else:
            print(f"[{Fore.RED}FAIL{Style.RESET_ALL}] Passwords do not require uppercase characters")
            low_fails += 1

        lowercase_requires = require_lowercase()
        if lowercase_requires is None:
            print(f"[{Fore.RED}FAIL{Style.RESET_ALL}] No account password policy exists")
            low_fails += 1
        elif lowercase_requires:
            print(f"[{Fore.GREEN}PASS{Style.RESET_ALL}] Passwords require a lowercase character")
            total_passes += 1
        else:
            print(f"[{Fore.RED}FAIL{Style.RESET_ALL}] Passwords do not require lowercase characters")
            low_fails += 1

        password_age_maximum = max_password_age()
        if password_age_maximum is None:
            print(f"[{Fore.RED}FAIL{Style.RESET_ALL}] Password expiration is not enabled")
            medium_fails += 1
        elif password_age_maximum <= 90:
            print(f"[{Fore.GREEN}PASS{Style.RESET_ALL}] Maximum password age is {password_age_maximum} days")
            total_passes += 1
        else:
            print(f"[{Fore.RED}FAIL{Style.RESET_ALL}] Maximum password age is {password_age_maximum} days")
            medium_fails += 1

        days = days_since_password_use(user)
        if days is None:
            print(f"[{Fore.YELLOW}INFO{Style.RESET_ALL}] User has never logged in or has no console password")
            total_info += 1
        elif days > 90:
            print(f"[{Fore.RED}FAIL{Style.RESET_ALL}] Password was last used {days} days ago")
            medium_fails += 1
        else:
            print(f"[{Fore.GREEN}PASS{Style.RESET_ALL}] Password was last used {days} days ago")
            total_passes += 1

        scan_results["password_policy"] = {
            "minimum_length": minimum_length_value,
            "require_symbols": symbols_required,
            "require_numbers": numbers_required,
            "require_uppercase": uppercase_requires,
            "require_lowercase": lowercase_requires,
            "max_password_age": password_age_maximum
        }

    for region in target_regions:
        print(f"\n=====================")
        print(f"Scanning region: {region}")
        print(f"=====================")

#S3 bucket checks
        print("\n=== S3 Bucket Checks ===")
        buckets = list_buckets()
        print(f"Found {len(buckets)} bucket(S)")
        for bucket in buckets:
            print(bucket["Name"])

        for bucket in buckets:
            print(f"\nBucket: {bucket['Name']}")

            is_public = is_bucket_public(bucket["Name"])
            if is_public:
                print(f"[{Fore.RED}FAIL{Style.RESET_ALL}] Bucket is publicly accessible")
                critical_fails += 1
            else:
                print(f"[{Fore.GREEN}PASS{Style.RESET_ALL}] Bucket is not publicly accessible")
                total_passes += 1

            versioning_enabled = is_versioning_enabled(bucket["Name"])
            if versioning_enabled:
                print(f"[{Fore.GREEN}PASS{Style.RESET_ALL}] Bucket versioning is enabled")
                total_passes += 1
            else:
                print(f"[{Fore.RED}FAIL{Style.RESET_ALL}] Bucket versioning is not enabled")
                low_fails += 1

            encryption_enabled = is_encryption_enabled(bucket["Name"])
            if encryption_enabled:
                print(f"[{Fore.GREEN}PASS{Style.RESET_ALL}] Bucket encryption is enabled")
                total_passes += 1
            else:
                print(f"[{Fore.RED}FAIL{Style.RESET_ALL}] Bucket encryption is not enabled")
                medium_fails += 1

            logging_enabled = is_logging_enabled(bucket["Name"])
            if logging_enabled:
                print(f"[{Fore.GREEN}PASS{Style.RESET_ALL}] Bucket logging is enabled")
                total_passes += 1
            else:
                print(f"[{Fore.RED}FAIL{Style.RESET_ALL}] Bucket logging is not enabled")
                low_fails += 1

            lifecycle_enabled = has_lifecycle_rules(bucket["Name"])
            if lifecycle_enabled:
                print(f"[{Fore.GREEN}PASS{Style.RESET_ALL}] Bucket has an enabled lifecycle rule")
                total_passes += 1
            else:
                print(f"[{Fore.RED}FAIL{Style.RESET_ALL}] Bucket has no enabled lifecycle rules")
                low_fails += 1

            policy_public = is_bucket_policy_public(bucket["Name"])
            if policy_public:
                print(f"[{Fore.RED}FAIL{Style.RESET_ALL}] Bucket policy allows public access")
                critical_fails += 1
            else:
                print(f"[{Fore.GREEN}PASS{Style.RESET_ALL}] Bucket policy is not public")
                total_passes += 1

            acl_public = is_bucket_acl_public(bucket["Name"])
            if acl_public:
                print(f"[{Fore.RED}FAIL{Style.RESET_ALL}] Bucket ACL allows public access")
                critical_fails += 1
            else:
                print(f"[{Fore.GREEN}PASS{Style.RESET_ALL}] Bucket ACL does not allow public access")
                total_passes += 1

            scan_results["s3_buckets"].append({
            "bucket_name": bucket["Name"],
            "is_public": is_bucket_public(bucket["Name"]),
            "versioning_enabled": is_versioning_enabled(bucket["Name"]),
            "encryption_enabled": is_encryption_enabled(bucket["Name"]),
            "logging_enabled": is_logging_enabled(bucket["Name"]),
            "lifecycle_rules": has_lifecycle_rules(bucket["Name"]),
            "policy_public": is_bucket_policy_public(bucket["Name"]),
            "acl_public": is_bucket_acl_public(bucket["Name"])
        })

        #EC2 Checks
        print("\n=== EC2 Checks ===")
        security_groups = list_security_groups()
        print(f"Found {len(security_groups)} security group(s)")

        for group in security_groups:
            print(f"\nSecurity Group: {group['GroupName']}")
            sensitive_port_public = is_sensitive_port_public(group)
            if sensitive_port_public:
                print(f"[{Fore.RED}FAIL{Style.RESET_ALL}] Security group exposes SSH or RDP to the internet")
                critical_fails += 1
            else:
                print(f"[{Fore.GREEN}PASS{Style.RESET_ALL}] Security group does not expose SSH or RDP to the internet")
                total_passes += 1

        scan_results["security_groups"].append({
            "group_name": group["GroupName"],
            "sensitive_port_public": is_sensitive_port_public(group)
        })

        #RDS Database Checks
        print("\n=== RDS Database Checks ===")
        rds_instances = list_rds_instances()
        print(f"Found {len(rds_instances)} RDS database instance(s)")

        for db in rds_instances:
            db_identifier = db["DBInstanceIdentifier"]
            print(f"\nRDS Instance: {db_identifier}")
            is_public = is_rds_publicly_accessible(db)
            if is_public:
                print(f"[{Fore.RED}FAIL{Style.RESET_ALL}] RDS database instance is publicly accessible")
                critical_fails += 1
            else:
                print(f"[{Fore.GREEN}PASS{Style.RESET_ALL}] RDS database instance is not publicly accessible")
                total_passes += 1

            scan_results["rds_instances"].append({
                "db_identifier": db_identifier,
                "publicly_accessible": is_public
            })

            scan_results["rds_instances"].append({
            "db_identifier": db_identifier,
            "publicly_accessible": is_rds_publicly_accessible(db)
        })
        
        #CloudTrail Checks
        print("\n=== CloudTrail Checks ===")
        trail_status = check_cloudtrail_status()
        if trail_status["Enabled"]:
            print(f"[{Fore.GREEN}PASS{Style.RESET_ALL}] CloudTrail is active and logging (Multi-Region: {trail_status.get('MultiRegion', False)})")
            total_passes += 1
        else:
            print(f"[{Fore.RED}FAIL{Style.RESET_ALL}] Cloudtrail is not properly configured or logging: {trail_status.get('Reason', 'Unknown')}")
            high_fails += 1

        scan_results["cloudtrail"] = trail_status

    print("\n========================================")
    print(f"{Fore.CYAN}Cloud Security Risk Assessment{Style.RESET_ALL}")
    print("========================================\n")
    print(f"Regions Scanned: {len(target_regions)}")
    print(f"Total Checks Passed: {Fore.GREEN}{total_passes}{Style.RESET_ALL}")
    print(f"Critical Findings: {Fore.RED}{critical_fails}{Style.RESET_ALL}")
    print(f"High Findings: {Fore.RED}{high_fails}{Style.RESET_ALL}")
    print(f"Medium Findings: {Fore.YELLOW}{medium_fails}{Style.RESET_ALL}")
    print(f"Low Findings: {Fore.YELLOW}{low_fails}{Style.RESET_ALL}")
    print(f"Informational Findings: {Fore.BLUE}{total_info}{Style.RESET_ALL}")
    print("========================================\n")
        
    save_scan_report(scan_results)
    print_risk_table(total_passes, critical_fails, high_fails, medium_fails, low_fails, total_info, len(target_regions))

if __name__ == "__main__":
    main()
