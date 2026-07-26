import boto3

def list_iam_users():
    iam_client = boto3.client("iam")
    response = iam_client.list_users()

    users = response["Users"]

    print(f"IAM users found: {len(users)}")

    for user in users:
        print(f"- {user['UserName']}")