import requests
import json

url = "http://localhost:5000/check"
payload = "UNION+SELECT+1,user,pass+from+users --"
data = {"payload": payload}

print(f"Testing payload: {payload}")

try:
    response = requests.post(url, json=data, timeout=5)
    print("Status Code:", response.status_code)
    print("Response JSON:", json.dumps(response.json(), indent=2))
except Exception as e:
    print("Error:", e)
