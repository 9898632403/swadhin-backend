import requests

url = "http://127.0.0.1:5000/debug-signup"
data = {
    "email": "test@gmail.com",
    "password": "123456",
    "username": "testuser"
}

try:
    res = requests.post(url, json=data)
    print("Status:", res.status_code)
    print("Response:", res.json())
except Exception as e:
    print("Error:", str(e))
