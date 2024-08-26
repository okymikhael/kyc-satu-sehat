import base64
import json
import os
import tempfile
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import requests

class KYC:
    # def __init__(self):
        # self.token = 'zoPGXJRA5ODMwqCEYf7AjL2yllfX'
        
    def generate_key(self):
        # Generate a new RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        # Extract the public key in PEM format
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Extract the private key in PEM format
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        return {
            'publicKey': public_key_pem.decode(),
            'privateKey': private_key_pem.decode()
        }

    def import_rsa_key(self, pem):
        # Load the public key from PEM format
        public_key = serialization.load_pem_public_key(
            pem.encode(),
            backend=default_backend()
        )
        return public_key

    def generate_symmetric_key(self):
        return os.urandom(32)

    def generate_rsa_key_pair(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return {
            'privateKey': private_key,
            'publicKey': public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
        }

    def format_message(self, data):
        data_as_base64 = base64.b64encode(data).decode()
        return f"-----BEGIN ENCRYPTED MESSAGE-----\r\n{data_as_base64}\r\n-----END ENCRYPTED MESSAGE-----"

    def aes_encrypt(self, data, symmetric_key):
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(symmetric_key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return iv + ciphertext + encryptor.tag

    def aes_decrypt(self, encrypted_data, symmetric_key):
        iv = encrypted_data[:12]
        tag = encrypted_data[-16:]
        ciphertext = encrypted_data[12:-16]
        cipher = Cipher(algorithms.AES(symmetric_key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    def encrypt_message(self, message, pub_pem):
        aes_key = self.generate_symmetric_key()
        server_key = serialization.load_pem_public_key(pub_pem.encode(), backend=default_backend())
        wrapped_aes_key = server_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encrypted_message = self.aes_encrypt(message.encode(), aes_key)
        payload = wrapped_aes_key + encrypted_message
        return self.format_message(payload)

    def decrypt_message(self, message, private_key):
        begin_tag = '-----BEGIN ENCRYPTED MESSAGE-----'
        end_tag = '-----END ENCRYPTED MESSAGE-----'
        message_contents = message[len(begin_tag)+1:-len(end_tag)-1].strip()
        binary_der_string = base64.b64decode(message_contents)
        
        wrapped_key_length = 256
        wrapped_key = binary_der_string[:wrapped_key_length]
        encrypted_message = binary_der_string[wrapped_key_length:]
        
        # Load the private key
        key = serialization.load_pem_private_key(
            private_key.encode(),
            password=None,
            backend=default_backend()
        )
        
        try:
            # Attempt to decrypt the wrapped key
            aes_key = key.decrypt(
                wrapped_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except ValueError as e:
            print(f"Decryption of wrapped key failed: {e}")
            print("Wrapped key:", wrapped_key.hex())
            return None

        try:
            # Attempt to decrypt the message
            decrypted_message = self.aes_decrypt(encrypted_message, aes_key)
            return decrypted_message.decode()
        except Exception as e:
            print(f"Decryption of message failed: {e}")
            return None

    def generate_url(self, agen, nik_agen):
        key_pair = self.generate_key()
        public_key = key_pair['publicKey']
        private_key = key_pair['privateKey']

        # access_token = self.token()  # Assuming this method exists in your class
        access_token = 'zoPGXJRA5ODMwqCEYf7AjL2yllfX'

        api_url = 'https://api-satusehat-stg.dto.kemkes.go.id/kyc/v1/generate-url'

        pub_pem = '''-----BEGIN PUBLIC KEY-----
        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwqoicEXIYWYV3PvLIdvB
        qFkHn2IMhPGKTiB2XA56enpPb0UbI9oHoetRF41vfwMqfFsy5Yd5LABxMGyHJBbP
        +3fk2/PIfv+7+9/dKK7h1CaRTeT4lzJBiUM81hkCFlZjVFyHUFtaNfvQeO2OYb7U
        kK5JrdrB4sgf50gHikeDsyFUZD1o5JspdlfqDjANYAhfz3aam7kCjfYvjgneqkV8
        pZDVqJpQA3MHAWBjGEJ+R8y03hs0aafWRfFG9AcyaA5Ct5waUOKHWWV9sv5DQXmb
        EAoqcx0ZPzmHJDQYlihPW4FIvb93fMik+eW8eZF3A920DzuuFucpblWU9J9o5w+2
        oQIDAQAB
        -----END PUBLIC KEY-----'''

        data = {
            'agent_name': agen,
            'agent_nik': nik_agen,
            'public_key': public_key,
        }

        json_data = json.dumps(data)
        encrypted_payload = self.encrypt_message(json_data, pub_pem)

        headers = {
            'Content-Type': 'text/plain',
            'Authorization': f'Bearer {access_token}'
        }

        response = requests.post(api_url, data=encrypted_payload, headers=headers)

        if response.status_code != 200:
            print(f'HTTP error: {response.status_code}')
            return None
        
        # return response.text

        return self.decrypt_message(response.text, private_key)
    
kyc = KYC()
# Call the generate_url method with the provided parameters
result = kyc.generate_url('Doyok Putih', '################')

# Print the result
print("Result of generate_url:")
print(result)