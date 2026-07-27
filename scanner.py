import boto3
from checks.iam import list_iam_users, has_mfa_enabled, has_console_access

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

    print(f"Found {len(users)} IAM users.\n")

    for user in users:
        if has_console_access(user["UserName"]):
            print(f"[PASS] {user['UserName']}: Console access is enabled")

            if has_mfa_enabled(user["UserName"]):
                print(f"[PASS] {user['UserName']}: MFA is enabled")
            else:
                print(f"[FAIL] {user['UserName']}: MFA is not enabled")

        else:
            print(f"[INFO] {user['UserName']}: No console access (MFA not applicable)")

if __name__ == "__main__":
    main()