import boto3
from checks.iam import (key_creation_date, list_iam_users, has_mfa_enabled, has_console_access, list_access_keys,has_admin_access)

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

# Check each user for console access, MFA and access keys
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
            print(f"[INFO] {user['UserName']}: " f"Access Key {key['AccessKeyId']} is {key['Status']}")

        key_date = key_creation_date(key['CreateDate'])
        if key_date > 90:
            status = "FAIL"
            message = "older than 90 days"
        else:
            status = "PASS"
            message = "less than 90 days"
        print(f"[{status}] Access Key {key['AccessKeyId']} for user "f"{user['UserName']} is {message} ({key_date} days old)")

        has_admin = has_admin_access(user['UserName'])
        if has_admin == True:
            status = "PASS"
            message = "User has administrative privelages"
        else:
            status = "FAIL"
            message = "User does not have administrative privelages"
        print(f"[{status}] {message}")



if __name__ == "__main__":
    main()