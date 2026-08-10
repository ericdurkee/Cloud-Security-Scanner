import boto3
from botocore.exceptions import ClientError

def list_buckets():
    s3_client = boto3.client("s3")
    response = s3_client.list_buckets()
    return response["Buckets"]

def is_bucket_public(bucket_name):
    s3_client = boto3.client("s3")
    response = s3_client.get_public_access_block(Bucket=bucket_name)
    config = response["PublicAccessBlockConfiguration"]
    return not all(config.values())

def is_versioning_enabled(bucket_name):
    s3_client = boto3.client("s3")
    response = s3_client.get_bucket_versioning(Bucket=bucket_name)
    if response.get("Status") == "Enabled":
        return True
    else:
        return False

def is_encryption_enabled(bucket_name):
    s3_client = boto3.client("s3")
    try:
        s3_client.get_bucket_encryption(Bucket=bucket_name)
        return True
    except ClientError:
        return False

def is_logging_enabled(bucket_name):
    s3_client = boto3.client("s3")
    response = s3_client.get_bucket_logging(Bucket=bucket_name)
    if response.get("LoggingEnabled"):
        return True
    else:
        return False

def has_lifecycle_rules(bucket_name):
    s3_client = boto3.client("s3")
    try:
        response = s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
        rules = response["Rules"]
        for rule in rules:
            if rule["Status"] == "Enabled":
                return True
        return False
    except ClientError:
        return False

def is_bucket_policy_public(bucket_name):
    s3_client = boto3.client("s3")
    try:
        response = s3_client.get_bucket_policy_status(Bucket=bucket_name)
        if response["PolicyStatus"]["IsPublic"]:
            return True
        else:
            return False
    except ClientError:
        return False

def is_bucket_acl_public(bucket_name):
    s3_client = boto3.client("s3")
    try:
        response = s3_client.get_bucket_acl(Bucket=bucket_name)
        grants = response["Grants"]
        for grant in grants:
            grantee = grant["Grantee"]
            uri = grantee.get("URI", "")
            if uri.endswith("AllUsers") or uri.endswith("AuthenticatedUsers"):
                return True
        return False
    except ClientError:
        return False
