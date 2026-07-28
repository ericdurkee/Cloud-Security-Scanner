from datetime import datetime, timezone
import boto3

def list_iam_users():
    iam_client = boto3.client("iam")
    response = iam_client.list_users()

    return response["Users"]

def has_mfa_enabled(username):
    iam_client = boto3.client("iam")
    response = iam_client.list_mfa_devices(UserName = username)

    return len(response["MFADevices"]) > 0

def has_console_access(username):
    iam_client = boto3.client("iam")

    try:
        iam_client.get_login_profile(UserName=username)
        return True
    except iam_client.exceptions.NoSuchEntityException:
        return False

def list_access_keys(username):
    iam_client = boto3.client("iam")
    response = iam_client.list_access_keys(UserName=username)
    return response["AccessKeyMetadata"]

def key_creation_date(CreateDate):
    current_time = datetime.now(timezone.utc)
    difference = current_time - CreateDate
    return difference.days

def has_admin_access(username):
    iam_client = boto3.client("iam")
    response = iam_client.list_attached_user_policies(UserName=username)
    policies = response["AttachedPolicies"]

    for policy in policies:
        if policy["PolicyName"] == "AdministratorAccess":
            return True
    return False

def get_last_key_usage(access_key_id):
    iam_client = boto3.client("iam")
    response = iam_client.get_access_key_last_used(AccessKeyId=access_key_id)
    return response["AccessKeyLastUsed"].get("LastUsedDate")





