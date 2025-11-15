# RSA Cryptosystem Implementation

This is an RSA encryption implementation based on the 
[Understanding Cryptography: From Established Symmetric and Asymmetric Ciphers to Post-Quantum Algorithms](https://learn.lajevardi.id.ir/Cryptography/Refrence/2.pdf) textbook. 
It includes both a Python library and a Flask REST API for encryption, decryption, and digital signatures.


---

## How to Run Tests

### Core RSA Tests (no installation needed)

```bash
cd rsa
python3 test_rsa.py
```

You should see: `46 tests passed`

### Flask API Tests (requires Flask)

```bash
# Create virtual environment
python3 -m venv venv

# Activate it
source venv/bin/activate

# Install Flask
pip install flask flask-cors

# Run tests
python test_rsa.py         # 46 tests
python test_flask_api.py   # 21 tests
```

Total: 67 tests, all passing.

---

## How to Start the Flask Server

```bash
# Make sure venv is activated
source venv/bin/activate

# Start server
python flask_rsa.py
```

Server runs on `http://localhost:8080`

Test it:
```bash
curl http://localhost:8080/api/health
```

---

## What's Implemented

### RSA Core Functions

**Key Generation:**
- Generate two distinct prime numbers (p, q) using Miller-Rabin primality test
- Calculate n = p × q
- Calculate φ(n) = (p-1)(q-1)
- Choose public exponent e where gcd(e, φ(n)) = 1
- Calculate private exponent d = e⁻¹ mod φ(n)

**Encryption/Decryption:**
- Encrypt: c = m^e mod n
- Decrypt: m = c^d mod n

**Digital Signatures:**
- Sign: signature = hash(message)^d mod n
- Verify: hash(message) == signature^e mod n
- Uses SHA-256 for hashing

**Mathematical Functions:**
- Miller-Rabin primality testing
- Extended Euclidean Algorithm for modular inverse
- Fast modular exponentiation
- GCD calculation

**Supported Key Sizes:**
- 256 bits (testing)
- 512 bits (demos)
- 1024 bits
- 2048 bits

---

## Python Usage

### Simple API

```python
from rsa import generate_keypair, encrypt, decrypt, sign, verify

# Generate keys
keys = generate_keypair(512)

# Encrypt
ciphertext = encrypt("Hello!", keys['public_key'], keys['size'])

# Decrypt
plaintext = decrypt(ciphertext, keys['private_key'], keys['size'])

# Sign
sig = sign("Document", keys['private_key'], keys['size'])

# Verify
is_valid = verify("Document", sig['signature'], sig['message_hash'],
                   keys['public_key'], keys['size'])
```

### Object-Oriented API

```python
from rsa_system import RSA, TextConverter

# Generate keys
keypair = RSA.generate_keypair(bits=512)
public_key = keypair.get_public_key()
private_key = keypair.get_private_key()

# Encrypt
message = 12345
ciphertext = RSA.encrypt(message, public_key)
decrypted = RSA.decrypt(ciphertext, private_key)
```

---

## Flask API Endpoints

All endpoints use `http://localhost:8080/api/`

### GET /api/health
Check if server is running.

```bash
curl http://localhost:8080/api/health
```

### POST /api/generate-keys
Generate RSA key pair.

```bash
curl -X POST http://localhost:8080/api/generate-keys \
  -H "Content-Type: application/json" \
  -d '{"size": 512, "session_id": "test"}'
```

### POST /api/encrypt
Encrypt a message.

```bash
curl -X POST http://localhost:8080/api/encrypt \
  -H "Content-Type: application/json" \
  -d '{"message": "Hello!", "session_id": "test"}'
```

### POST /api/decrypt
Decrypt a message.

```bash
curl -X POST http://localhost:8080/api/decrypt \
  -H "Content-Type: application/json" \
  -d '{"ciphertext": "YOUR_CIPHERTEXT", "session_id": "test"}'
```

### POST /api/sign
Sign a message.

```bash
curl -X POST http://localhost:8080/api/sign \
  -H "Content-Type: application/json" \
  -d '{"message": "Document", "session_id": "test"}'
```

### POST /api/verify
Verify a signature.

```bash
curl -X POST http://localhost:8080/api/verify \
  -H "Content-Type: application/json" \
  -d '{"message": "Document", "signature": "SIG", "message_hash": "HASH", "session_id": "test"}'
```

---

## Files

**Core Implementation:**
- `rsa.py` - Simple function-based API
- `rsa_system.py` - Object-oriented RSA implementation
- `test_rsa.py` - 46 unit tests

**Flask API:**
- `flask_rsa.py` - REST API server
- `test_flask_api.py` - 21 API tests

**Other:**
- `requirements.txt` - Python dependencies

---

## Testing Coverage

**46 Core RSA Tests:**
- Mathematical functions (GCD, modular inverse, etc.)
- Prime number generation
- Key pair generation
- Encryption/decryption
- Text conversion
- Edge cases
- Integration tests

**21 Flask API Tests:**
- Health check
- Key generation
- Encryption/decryption
- Digital signatures
- Error handling
- Session management
- Unicode support

---

## Troubleshooting

**Flask not installed:**
```bash
source venv/bin/activate
pip install flask flask-cors
```

**Port 8080 in use:**
Edit `flask_rsa.py` line 431, change port to 8081.

**Virtual environment not found:**
```bash
python3 -m venv venv
source venv/bin/activate
```

**Tests fail:**
Make sure you're in the `rsa` directory.

---

## Important Notes

This is an educational implementation. It uses textbook RSA without OAEP padding. Do not use in production.

For production use:
- Use established libraries (`cryptography`, `PyCryptodome`)
- Use minimum 2048-bit keys
- Use OAEP padding for encryption
- Use PSS for signatures

---

## Textbook Compliance

Implementation follows [Understanding Cryptography: From Established Symmetric and Asymmetric Ciphers to Post-Quantum Algorithms](https://learn.lajevardi.id.ir/Cryptography/Refrence/2.pdf) textbook:

- Key generation algorithm (5 steps) - Complete
- Miller-Rabin primality test - Implemented
- Extended Euclidean Algorithm - Implemented
- RSA encryption (c = m^e mod n) - Implemented
- RSA decryption (m = c^d mod n) - Implemented
- Digital signatures with SHA-256 - Implemented

---

## Quick Commands

```bash
# Run core tests
python3 test_rsa.py

# Setup Flask
python3 -m venv venv
source venv/bin/activate
pip install flask flask-cors

# Run all tests
python test_rsa.py
python test_flask_api.py

# Start server
python flask_rsa.py

# Test server
curl http://localhost:8080/api/health
```