import unittest
import json
import hmac
import hashlib
from app import app, SECRET_KEY

class TestWebhookIntegration(unittest.TestCase):

    def setUp(self):
        # Setup Flask test client
        self.client = app.test_client()
        self.payload = '{"key": "value"}'
        self.valid_signature = hmac.new(SECRET_KEY, self.payload.encode(), hashlib.sha256).hexdigest()
        self.invalid_signature = "invalid_signature"
    
    def test_webhook_valid_request(self):
        """ Test a valid payload with correct signature """
        response = self.client.post(
            "/webhook", 
            data=self.payload,
            headers={"X-Signature": self.valid_signature}
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Webhook received and verified", response.data)
    
    def test_webhook_invalid_signature(self):
        """ Test an invalid signature """
        response = self.client.post(
            "/webhook", 
            data=self.payload,
            headers={"X-Signature": self.invalid_signature}
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"Invalid signature", response.data)
    
    def test_webhook_missing_signature(self):
        """ Test a missing signature header """
        response = self.client.post(
            "/webhook", 
            data=self.payload
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"Signature header missing", response.data)
    
    def test_webhook_invalid_json(self):
        """ Test invalid JSON payload """
        invalid_json_payload = '{"key": "value"'  # Missing closing brace
        response = self.client.post(
            "/webhook", 
            data=invalid_json_payload,
            headers={"X-Signature": self.valid_signature}
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"Invalid JSON payload", response.data)
    
    def test_webhook_empty_payload(self):
        """ Test empty payload with correct signature """
        empty_payload = ""
        empty_signature = hmac.new(SECRET_KEY, empty_payload.encode(), hashlib.sha256).hexdigest()
        response = self.client.post(
            "/webhook", 
            data=empty_payload,
            headers={"X-Signature": empty_signature}
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"Invalid JSON payload", response.data)

if __name__ == "__main__":
    unittest.main()
