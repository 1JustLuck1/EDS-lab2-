from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
import os

app = Flask(__name__)

#Генерация ключей RSA для сервера.
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
public_key = private_key.public_key()

#Сериализация публичного ключа сервера.
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

#Словарь для хранения публичных ключей клиентов.
clients = {}

#Роут для возвращения публичного ключа сервера.
@app.route('/public_key', methods=['GET'])
def get_public_key():
    return public_pem

#Регистрация публичного ключа клиента.
@app.route('/register_client', methods=['POST'])
def register_client():
    data = request.json
    client_id = data.get('client_id', 'default_client')
    clients[client_id] = serialization.load_pem_public_key(data['public_key'].encode('utf-8'))
    return jsonify({'status': 'success'})

#Генерация и подпись случайного сообщения.
@app.route('/generate_message', methods=['GET'])
def generate_message():
    message = os.urandom(32)
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return jsonify({'message': message.hex(), 'signature': signature.hex()})

#Проверка подписи клиента.
@app.route('/verify', methods=['POST'])
def verify():
    data = request.json
    message = bytes.fromhex(data['message'])
    signature = bytes.fromhex(data['signature'])
    client_id = data.get('client_id', 'default_client')

    if client_id not in clients:
        return jsonify({'status': 'failed', 'error': 'Client not registered'})

    try:
        clients[client_id].verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return jsonify({'status': 'verified'})
    except Exception as e:
        return jsonify({'status': 'failed', 'error': str(e)})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)