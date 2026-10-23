import boto3
import pytest
from moto import mock_aws
from checks.s3 import list_buckets, is_bucket_public
from checks.iam import list_iam_users, has_mfa_enabled

@mock_aws
def test_s3_mock_checks():
    conn = boto3.client("s3", region_name="us-east-1")
    conn.create_bucket(Bucket="secure-test-bucket")

    conn.put_public_access_block(
        Bucket="secure-test-bucket",
        PublicAccessBlockConfiguration={
            'BlockPublicAcls': True,
            'IgnorePublicAcls': True,
            'BlockPublicPolicy': True,
            'RestrictPublicBuckets': True
        }
    )

    buckets = list_buckets()
    assert len(buckets) == 1
    assert buckets[0]["Name"] == 'secure-test-bucket'

    assert is_bucket_public("secure-test-bucket") is False

@mock_aws
def test_iam_mock_checks():
    conn = boto3.client("iam", region_name="us-east-1")
    conn.create_user(UserName="audit-test-user")

    users = list_iam_users()
    assert len(users) == 1
    assert users[0]["UserName"] == "audit-test-user"
