import boto3

def list_iam_users():
    iam_client = boto3.client("iam")
    response = iam_client.list_users()

    return response["Users"]

def has_mfa_enabled(username):
    iam_client = boto3.client("iam")
    response = iam_client.list_mfa_devices(UserName = username)

    return len(response["MFADevices"]) > 0