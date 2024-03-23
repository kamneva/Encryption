
import requests
import rsa

from base64 import b64encode
from os import remove as remove_file

class APIRequest:
    def __init__(self) -> None:
        self.base_url = "http://127.0.0.1:5000"

        (self.public_key, self.private_key) = rsa.newkeys(2048)

    def verify_message(self, message, signature) -> bool:
        message_file = open("message", "w")
        message_file.write(message)
        message_file.close()

        signature_file = open("signature", "w")
        signature_file.write(b64encode(signature).decode())
        signature_file.close()

        message_file = open("message", "r")
        signature_file = open("signature", "r")

        url = f"{self.base_url}/verify-message"
        params = {
            "n" : self.public_key.n,
            "e" : self.public_key.e
        }
        files = {
            "message" : message_file,
            "signature" : signature_file
        }

        response = requests.post(url, params=params, files=files)

        message_file.close()
        remove_file("message")

        signature_file.close()
        remove_file("signature")

        return response.status_code == 200

    def get(self, url, params = None):
        response = requests.get(url, params=params)

        if response.status_code != 200:
            return None

        return response.json()

    def get_public_key(self):
        url = f"{self.base_url}/public-key"
        return self.get(url)

    def get_message(self, correct):
        url = f"{self.base_url}/message"
        params = { "type" : "correct" if correct else "incorrect" }
        return self.get(url, params)

request = APIRequest()