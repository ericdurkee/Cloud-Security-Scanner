import boto3
from checks.iam import (key_creation_date, list_iam_users, has_mfa_enabled, has_console_access, list_access_keys, has_admin_access, get_last_key_usage, active_key_count, inline_policy_count,
get_account_summary, root_mfa_enabled, root_access_keys_present, get_password_policy, minimum_length, require_symbols, require_numbers, require_uppercase, require_lowercase, max_password_age,
days_since_password_use)
from checks.s3 import (list_buckets, is_bucket_public, is_versioning_enabled, is_encryption_enabled, is_logging_enabled, has_lifecycle_rules, is_bucket_policy_public, is_bucket_acl_public)
from checks.ec2 import (list_security_groups, is_sensitive_port_public)
from datetime import datetime, timezone

def main():
    print("\n=================================")
    print("Cloud Security Scanner v0.1")
    print("=================================")
    print("\nInitializing...")

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
            print(f"[PASS] {user['UserName']}: Console access is enabled")
            if has_mfa_enabled(user["UserName"]):
                print(f"[PASS] {user['UserName']}: MFA is enabled")
            else:
                print(f"[FAIL] {user['UserName']}: MFA is not enabled")
        else:
            print(f"[INFO] {user['UserName']}: No console access (MFA not applicable)")

        access_keys = list_access_keys(user["UserName"])
        for key in access_keys:
            print(
                f"[INFO] {user['UserName']}: "
                f"Access Key {key['AccessKeyId']} is {key['Status']}"
            )

            key_date = key_creation_date(key["CreateDate"])
            if key_date > 90:
                status = "FAIL"
                message = "older than 90 days"
            else:
                status = "PASS"
                message = "less than 90 days"
            print(
                f"[{status}] Access Key {key['AccessKeyId']} for user "
                f"{user['UserName']} is {message} ({key_date} day(s) old)")

            last_used = get_last_key_usage(key["AccessKeyId"])
            if last_used is None:
                status = "FAIL"
                message = "Access key has never been used"
            else:
                current_time = datetime.now(timezone.utc)
                difference = current_time - last_used
                days_since_used = difference.days
                if days_since_used > 90:
                    status = "FAIL"
                    message = f"Access key has not been used in {days_since_used} days"
                else:
                    status = "PASS"
                    message = f"Access key was used {days_since_used} days ago"
            print(f"[{status}] {message}")

            active_keys = active_key_count(access_keys)
            for key in access_keys:
                if active_keys > 1:
                    status = "FAIL"
                    message = f"User has {active_keys} active access key"
                else:
                    status = "PASS"
                    message = f"User has {active_keys} active access key"
                print(f"[{status}] {message}")

            inline_policy = inline_policy_count(user["UserName"])
            if inline_policy > 0:
                status = "FAIL"
                message = f"User has {inline_policy} inline polic"
                if inline_policy == 1:
                    message += "y"
                else:
                    message += "ies"
            else:
                status = "PASS"
                message = "User has no inline policies"
            print(f"[{status}] {message}")

        has_admin = has_admin_access(user["UserName"])
        if has_admin:
            status = "FAIL"
            message = "User has administrative privileges"
        else:
            status = "PASS"
            message = "User does not have administrative privileges"
        print(f"[{status}] {message}\n")

        #Root User Checks
        print("=== Root Account Checks ===\n")
        root_mfa = root_mfa_enabled()

        root_keys = root_access_keys_present()
        if root_keys:
            status = "FAIL"
            message = "Root access keys are present"
        else:
            status = "PASS"
            message = "No root access keys are present"
        print(f"[{status}] {message}")

        root_mfa = root_mfa_enabled()
        if root_mfa:
            status = "PASS"
            message = "Root user has mfa enabled\n"
        else:
            status = "FAIL"
            message = "Root user has no mfa enabled\n"
        print(f"[{status}] {message}")

        #Password Check
        print("=== Password Policy ===\n")
        password_policy = get_password_policy()

        minimum_length_value = minimum_length()
        if minimum_length_value is None:
            print("[FAIL] No account password policy exists")
        elif minimum_length_value >= 14:
            print(f"[PASS] Minimum password length is {minimum_length_value}")
        else:
            print(f"[FAIL] Minimum password length is only {minimum_length_value}; "
            "recommended minimum is 14")

        symbols_required = require_symbols()
        if symbols_required is None:
            print("[FAIL] No account password policy exists")
        elif symbols_required:
            print("[PASS] Passwords require a symbol")
        else:
            print("[FAIL] Passwords do not require symbols")

        numbers_required = require_numbers()
        if numbers_required is None:
            print("[FAIL] No account password policy exists")
        elif numbers_required:
            print("[PASS] Passwords require a number")
        else:
            print("[FAIL] Passwords do not require numbers")

        uppercase_requires = require_uppercase()
        if uppercase_requires is None:
            print("[FAIL] No account password policy exists")
        elif uppercase_requires:
             print("[PASS] Passwords require an uppercase character")
        else:
            print("[FAIL] Passwords do not require uppercase characters")

        lowercase_requires = require_lowercase()
        if lowercase_requires is None:
            print("[FAIL] No account password policy exists")
        elif lowercase_requires:
            print("[PASS] Passwords require a lowercase character")
        else:
            print("[FAIL] Passwords do not require lowercase characters")

        password_age_maximum = max_password_age()
        if password_age_maximum is None:
            print("[FAIL] Password expiration is not enabled")
        elif password_age_maximum <= 90:
            print(f"[PASS] Maximum password age is {password_age_maximum} days")
        else:
            print(f"[FAIL] Maximum password age is {password_age_maximum} days")

        days = days_since_password_use(user)
        if days is None:
            print("[INFO] User has never logged in or has no console password")
        elif days > 90:
            print(f"[FAIL] Password was last used {days} days ago")
        else:
            print(f"[PASS] Password was last used {days} days ago")

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
                print("[FAIL] Bucket is publicly accessible")
            else:
                print("[PASS] Bucket is not publicly accessible")

            versioning_enabled = is_versioning_enabled(bucket["Name"])
            if versioning_enabled:
                print("[PASS] Bucket versioning is enabled")
            else:
                print("[FAIL] Bucket versioning is not enabled")

            encryption_enabled = is_encryption_enabled(bucket["Name"])
            if encryption_enabled:
                print("[PASS] Bucket encryption is enabled")
            else:
                print("[FAIL] Bucket encryption is not enabled")

            logging_enabled = is_logging_enabled(bucket["Name"])
            if logging_enabled:
                print("[PASS] Bucket logging is enabled")
            else:
                print("[FAIL] Bucket logging is not enabled")

            lifecycle_enabled = has_lifecycle_rules(bucket["Name"])
            if lifecycle_enabled:
                print("[PASS] Bucket has an enabled lifecycle rule")
            else:
                print("[FAIL] Bucket has no enabled lifecycle rules")

            policy_public = is_bucket_policy_public(bucket["Name"])
            if policy_public:
                print("[FAIL] Bucket policy allows public access")
            else:
                print("[PASS] Bucket policy is not public")

            acl_public = is_bucket_acl_public(bucket["Name"])
            if acl_public:
                print("[FAIL] Bucket ACL allows public access")
            else:
                print("[PASS] Bucket ACL does not allow public access")

        #EC2 Checks
        print("\n=== EC2 Checks ===")
        security_groups = list_security_groups()
        print(f"Found {len(security_groups)} security group(s)")

        for group in security_groups:
            print(f"\nSecurity Group: {group['GroupName']}")
            sensitive_port_public = is_sensitive_port_public(group)
            if sensitive_port_public:
                print("[FAIL] Security group exposes SSH or RDP to the internet")
            else:
                print("[PASS] Security group does not expose SSH or RDP to the internet")

if __name__ == "__main__":
    main()
