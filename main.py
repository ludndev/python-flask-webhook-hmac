
import hmac
import hashlib
import json
import requests

APP_PORT=9090

SECRET_KEY = b"your-secret-key"

WEBHOOK_URL = f"http://127.0.0.1:{APP_PORT}/webhook"


payload = {
    "event": "payment.success",
    "amount": 100,
    "currency": "ABC",
    "order_id": "12345"
}

payload_str = json.dumps(payload)

def generate_hmac_signature(payload: str, secret_key: bytes) -> str:
    return hmac.new(secret_key, payload.encode(), hashlib.sha256).hexdigest()

signature = generate_hmac_signature(payload_str, SECRET_KEY)

headers = {
    "X-Signature": signature,
    "Content-Type": "application/json"
}

response = requests.post(WEBHOOK_URL, headers=headers, data=payload_str)

if response.status_code == 200:
    print("Webhook sent successfully and verified!")
    print("---")
    print(f"Status code: {response.status_code}")
    print(f"Response: \n{response.text}")
else:
    print("Failed to verify webhook.")
    print("---")
    print(f"Status code: {response.status_code}")
    print(f"Response: \n{response.text}")
