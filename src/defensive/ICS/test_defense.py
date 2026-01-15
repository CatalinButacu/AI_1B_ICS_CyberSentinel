import requests

url = "http://localhost:5000/check"

payload = {"query": "SE%20LECT * FROM use%72s "}

try:
    response = requests.post(url, json=payload)

    print("Status Code:", response.status_code)
    print("Text:", payload)
    print("Response from AI:", response.json())

except Exception as e:
    print("Error:", e)