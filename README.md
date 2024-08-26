# KYC Class

This Python module provides functionality for generating and managing RSA and AES keys, encrypting and decrypting messages, and interacting with a KYC (Know Your Customer) API.

## Features

- Generate RSA key pairs (public and private keys).
- Import RSA public keys from PEM format.
- Generate symmetric AES keys.
- Encrypt and decrypt messages using AES encryption.
- Encrypt messages with a symmetric key and wrap the key using RSA encryption.
- Decrypt messages and unwrap the symmetric key using RSA decryption.
- Generate a URL for KYC API requests.

## Requirements

- Python 3.x
- `cryptography` library
- `requests` library

## Installation

You can install the required libraries using pip:

```bash
pip install cryptography requests
```

## Running the App

To run the KYC application, follow these steps:

1. **Clone the repository:**

   ```bash
   git clone https://github.com/okymikhael/kyc-satu-sehat.git
   cd kyc-satu-sehat
   ```

2. **Install the required libraries:**

   Ensure you have Python 3.x installed, then run:

   ```bash
   pip install cryptography requests
   ```

3. **Run the application:**

   You can run the application by executing the following command in your terminal:

   ```bash
   python app/main.py
   ```

4. **Follow the usage instructions:**

   After running the application, follow the usage instructions provided in the "Usage" section to interact with the KYC class.

## Usage

1. **Instantiate the KYC class:**

   ```python
   from main import KYC

   kyc = KYC()
   ```

2. **Generate a URL for KYC:**

   Call the `generate_url` method with the agent's name and NIK:

   ```python
   result = kyc.generate_url('Agent Name', 'Agent NIK')
   print(result)
   ```

3. **Encrypt a message:**

   Use the `encrypt_message` method:

   ```python
   encrypted_message = kyc.encrypt_message('Your message', public_key_pem)
   ```

4. **Decrypt a message:**

   Use the `decrypt_message` method:

   ```python
   decrypted_message = kyc.decrypt_message(encrypted_message, private_key_pem)
   ```

## Example

```python
kyc = KYC()
result = kyc.generate_url('Doyok Putih', '################')
print("Result of generate_url:")
print(result)
```

## License

This project is licensed under the MIT License.