from flask import Flask, request, jsonify

from base64 import b64encode, b64decode

from hashlib import sha256
import rsa
import random

(server_public_key, server_private_key) = rsa.newkeys(2048)

app = Flask(__name__)

@app.route("/verify-message", methods=["POST"])
def send_message():
    message = request.files.get("message")
    signature = request.files.get("signature")

    n = request.args.get("n")
    e = request.args.get("e")

    if message is None:
        return "No message is sent", 400

    if signature is None:
        return "No signature is sent", 400

    if n is None or e is None:
        return "No public key is sent", 400

    hash = sha256(message.stream.read()).hexdigest().encode()
    signature_bytes = b64decode(signature.stream.read())
    public_key = rsa.PublicKey(int(n), int(e))

    try:
        rsa.verify(hash, signature_bytes, public_key)

    except rsa.VerificationError:
        return "Incorrect", 406

    return "Correct", 200

@app.route("/public-key", methods=["GET"])
def public_key():
    return jsonify({
        "n" : server_public_key.n,
        "e" : server_public_key.e
    })

@app.route("/message")
def message():
    type = request.args.get("type")
    if type not in ["correct", "incorrect"]:
        return None, 400

    #Рандомное сообщение для запроса
    message = "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", k=20))
    
    #Закидывается в хэш
    hash = sha256(message.encode())
    #На основе хэша формирование подписи
    signature = rsa.sign(hash.hexdigest().encode(), server_private_key, "SHA-1")

    #получение ответа от сервера и подписи
    return jsonify({
        "message" : message if type == "correct" else message + "Fake data",
        "signature" : b64encode(signature).decode()
    })

if __name__ == "__main__":
    app.run()