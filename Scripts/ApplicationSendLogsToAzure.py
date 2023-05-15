import requests
import json
import hmac
import hashlib
import base64
import datetime

def build_signature(
    customer_id, shared_key, date, content_length, method, content_type, resource
):
    x_headers = "x-ms-date:" + date
    string_to_hash = (
        method
        + "\n"
        + str(content_length)
        + "\n"
        + content_type
        + "\n"
        + x_headers
        + "\n"
        + resource
    )
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8")
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(
        hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()
    )
    authorization = f"SharedKey {customer_id}:{encoded_hash.decode('utf-8')}"
    return authorization

def send_logs_to_azure(logs, workspace_id, workspace_key):
    method = "POST"
    content_type = "application/json"
    resource = "/api/logs"
    rfc1123date = datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
    content_length = len(logs)

    signature = build_signature(
        workspace_id,
        workspace_key,
        rfc1123date,
        content_length,
        method,
        content_type,
        resource,
    )

    uri = f"https://{workspace_id}.ods.opinsights.azure.com{resource}?api-version=2016-04-01"

    headers = {
        "content-type": content_type,
        "Authorization": signature,
        "Log-Type": "MyCustomLogs",  # Change this to your desired log type
        "x-ms-date": rfc1123date,
    }

    response = requests.post(uri, data=logs, headers=headers)
    return response

workspace_id = "<your_workspace_id>"
workspace_key = "<your_workspace_key>"

# Replace the following line with the log data collected from your application
logs = json.dumps([{"property1": "value1", "property2": "value2"}])

response = send_logs_to_azure(logs, workspace_id, workspace_key)
print(response.status_code, response.text)
