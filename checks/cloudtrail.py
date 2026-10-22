import boto3
from botocore.exceptions import ClientError

def check_cloudtrail_status():
    trail_client = boto3.client("cloudtrail", region_name="us-east-1")
    try:
        response = trail_client.describe_trails()
        trails = response.get("trailList", [])

        if not trails:
            return {"Enabled": False, "Reason": "No trails configured"}
        
        for trail in trails:
            trail_name = trail["Name"]
            status_resp = trail_client.get_trail_status(Name=trail_name)
            if status_resp.get("isLogging", False) and trail.get("IncludeGlobalServiceEvents", False):
                return {"Enabled": True, "MultiRegion": trail.get("IsMultiRegionTrail", False)}

        return {"Enabled": False, "Reason": "Trails exist but are not actively logging"}
    except ClientError:
        return {"Enabled": False, "Reason": "Unable to fetch CloudTrail configuration"}
        