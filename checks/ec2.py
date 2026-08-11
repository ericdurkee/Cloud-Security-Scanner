import boto3

def list_security_groups():
    ec2_client = boto3.client("ec2")
    response = ec2_client.describe_security_groups()
    return response["SecurityGroups"]

#Need to review
def is_sensitive_port_public(group):
    inbound_rules = group["IpPermissions"]
    for rule in inbound_rules:
        from_port = rule.get("FromPort")
        to_port = rule.get("ToPort")

        if from_port is None or to_port is None:
            continue

        if (from_port <= 22 <= to_port) or (from_port <= 3389 <= to_port):
            ip_ranges = rule["IpRanges"]
            for ip_range in ip_ranges:
                if ip_range["CidrIp"] == "0.0.0.0/0":
                    return True
    return False