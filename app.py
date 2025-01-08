import hmac
import hashlib
import json
from flask import Flask, jsonify, make_response, request, abort

app = Flask(__name__)

APP_PORT=9090
APP_DEBUG=True

SECRET_KEY = b"your-secret-key"

SIGNATURE_HEADER = "X-Signature"

def verify_hmac_signature(payload: str, received_signature: str) -> bool:
    """
    Verifies the HMAC signature of the received payload.
    """
    # create the HMAC from the payload and secret key
    computed_hmac = hmac.new(SECRET_KEY, payload.encode(), hashlib.sha256).hexdigest()
    
    # compare the received signature with the computed HMAC (constant time comparison to prevent timing attacks)
    return hmac.compare_digest(computed_hmac, received_signature)

@app.route("/webhook", methods=["POST"])
def webhook():
    payload = request.get_data(as_text=True)
    received_signature = request.headers.get(SIGNATURE_HEADER)
    
    if not received_signature:
        abort(make_response(jsonify(message="Signature header missing"), 400))

    # check HMAC signature
    if not verify_hmac_signature(payload, received_signature):
        abort(make_response(jsonify(message="Invalid signature"), 400))
    
    try:
        data = json.loads(payload)

        print("received_signature", received_signature)
        print("data", data)

        return make_response(jsonify(message="Webhook received and verified"), 200)
    except json.JSONDecodeError:
        abort(make_response(jsonify(message="Invalid JSON payload"), 400))

if __name__ == "__main__":
    app.run(port=APP_PORT, debug=APP_DEBUG)
