----------------------------------------Overview----------------------------------------

The Secure Chat Application enables two users to exchange messages securely over an untrusted environment using a hybrid encryption model. It combines asymmetric and symmetric cryptography to ensure confidentiality, integrity, and authenticity of messages.

The system uses RSA for secure key exchange and digital signatures, and AES for efficient message encryption.

----------------------------------------Key Features----------------------------------------

Hybrid encryption using RSA and AES

End-to-end encrypted messaging

Digital signatures for message authenticity

Authenticated encryption using AES-GCM

Local RSA key generation and storage (PEM format)

Desktop GUI built with Tkinter

JSON-based encrypted message handling

----------------------------------------Cryptographic Design----------------------------------------

The application follows a hybrid encryption workflow commonly used in secure communication systems:

A random AES session key is generated for each message

The plaintext message is encrypted using AES-GCM

The AES session key is encrypted using the recipient’s RSA public key (RSA-OAEP)

The sender signs the encrypted payload using RSA-PSS

The receiver verifies the signature and decrypts the message

This design ensures strong confidentiality and authenticity guarantees.

----------------------------------------Security Properties----------------------------------------

Confidentiality: Provided by AES-GCM symmetric encryption

Integrity: Ensured via authenticated encryption (GCM authentication tag)

Authenticity: Implemented using RSA-PSS digital signatures

Secure Key Exchange: RSA-OAEP encryption of session keys

Tamper Detection: Signature verification prior to decryption

----------------------------------------Technology Stack----------------------------------------

Language: Python 3

GUI Framework: Tkinter

Cryptography Library: PyCryptodome

Data Serialization: JSON

Key Format: PEM
