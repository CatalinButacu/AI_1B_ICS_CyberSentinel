import requests

url = "http://localhost:5000/check"

payload = {"query": "SELECT * FROM products WHERE id = 1"}

try:
    response = requests.post(url, json=payload)

    print("Status Code:", response.status_code)
    print("Text:", payload)
    print("Response from AI:", response.json())

except Exception as e:
    print("Error:", e)