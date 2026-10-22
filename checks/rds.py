import boto3
from botocore.exceptions import ClientError

def list_rds_instances():
    rds_client = boto3.client("rds", region_name="us-east-1")
    try:
        response = rds_client.describe_db_instances()
        return response["DBInstances"]
    except ClientError:
        return []

def is_rds_publicly_accessible(db_instance):
    return db_instance.get("PubliclyAccessible", False)
