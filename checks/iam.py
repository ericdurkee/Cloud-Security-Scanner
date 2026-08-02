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

def active_key_count(access_keys):
    active_count = 0
    for key in access_keys:
        if key["Status"] == "Active":
            active_count += 1
    return active_count

def inline_policy_count(username):
    iam_client = boto3.client("iam")
    response = iam_client.list_user_policies(UserName=username)
    policies = response["PolicyNames"]
    return len(policies)

def get_account_summary():
    iam_client = boto3.client("iam")
    response = iam_client.get_account_summary()
    summary = response["SummaryMap"]
    return summary

def root_mfa_enabled():
    summary = get_account_summary()
    return summary["AccountMFAEnabled"] == 1

def root_access_keys_present():
    summary = get_account_summary()
    return summary["AccountAccessKeysPresent"] == 1

def get_password_policy():
    iam_client = boto3.client("iam")
    try:
        response = iam_client.get_account_password_policy()
        return response["PasswordPolicy"]
    except iam_client.exceptions.NoSuchEntityException:
        return None

def minimum_length():
    policy = get_password_policy()
    if policy is None:
        return None
    return policy["MinimumPasswordLength"]

def require_symbols():
    policy = get_password_policy()
    if policy is None:
        return None
    return policy["RequireSymbols"]

def require_numbers():
    policy = get_password_policy()
    if policy is None:
        return None
    return policy["RequireNumbers"]

def require_uppercase():
    policy = get_password_policy()
    if policy is None:
        return None
    return policy["RequireUppercaseCharacters"]

def require_lowercase():
    policy = get_password_policy()
    if policy is None:
        return None
    return policy["RequireLowercaseCharacters"]

def max_password_age():
    policy = get_password_policy()
    if policy is None:
        return None
    return policy.get("MaxPasswordAge")
