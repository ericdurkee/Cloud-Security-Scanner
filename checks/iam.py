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

