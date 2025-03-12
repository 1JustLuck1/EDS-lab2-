import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization

SERVER_URL = 'http://server:5001'

#Генерация ключей RSA для клиента
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
public_key = private_key.public_key()

#Сериализация публичного ключа клиента
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

#Запрос публичного ключа сервера
def get_server_public_key():
    response = requests.get(f'{SERVER_URL}/public_key')
    return serialization.load_pem_public_key(response.content)

#Отправка публичного ключа клиента на сервер
def send_public_key_to_server():
    response = requests.post(f'{SERVER_URL}/register_client', json={
        'public_key': public_pem.decode('utf-8')
    })
    return response.json()

#Запрос генерации случайного сообщения на сервере
def generate_random_message():
    response = requests.get(f'{SERVER_URL}/generate_message')
    return response.json()

#Верификация сообщения с использованием публичного ключа
def verify_message(message, signature, public_key):
    try:
        public_key.verify(
            bytes.fromhex(signature),
            bytes.fromhex(message),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Verification failed: {e}")
        return False

if __name__ == '__main__':
    #Регистрация публичного ключа клиента на сервере
    send_public_key_to_server()

    #Сценарий 1
    message = b"My new message to server!"
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    response = requests.post(f'{SERVER_URL}/verify', json={
        'message': message.hex(),
        'signature': signature.hex()
    })
    print("Сценарий 1:", response.json())

    #Сценарий 2
    server_public_key = get_server_public_key()
    data = generate_random_message()
    if verify_message(data['message'], data['signature'], server_public_key):
        print("Сценарий 2: Сообщение успешно подтверждено")
    else:
        print("Сценарий 2: Ошибка верфикации сообщения")