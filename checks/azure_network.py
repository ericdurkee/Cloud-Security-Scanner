from azure.identity import AzureCliCredential
from azure.mgmt.network import NetworkManagementClient
import subprocess

def get_network_client(subscription_id):
    credential = AzureCliCredential()
    network_client = NetworkManagementClient(
        credential,
        subscription_id
    )
    return network_client

def get_subscription_id():
    result = subprocess.run(
        ["az", "account", "show", "--query", "id", "--output", "tsv"],
        capture_output=True,
        text=True
    )
    return result.stdout.strip()

print(get_subscription_id())