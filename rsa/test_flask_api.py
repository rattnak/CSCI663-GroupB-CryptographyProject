import unittest
import json
import sys
import warnings

# Check if Flask is installed before importing
try:
    from flask_rsa import app, keypairs
except ImportError as e:
    print("=" * 70)
    print("ERROR: Missing dependencies for Flask API tests")
    print("=" * 70)
    print()
    print(f"Import error: {e}")
    print()
    print("To run Flask API tests, install dependencies first:")
    print()
    print("  pip install flask flask-cors")
    print()
    print("Or install all dependencies:")
    print()
    print("  pip install -r requirements.txt")
    print()
    print("=" * 70)
    sys.exit(1)


class TestFlaskRSAAPI(unittest.TestCase):
    # Comprehensive test suite for Flask RSA API.
    # Tests all endpoints and edge cases.

    def setUp(self):
        # Set up test client and clear keypairs before each test.
        self.app = app.test_client()
        self.app.testing = True
        keypairs.clear()
        # Suppress the OAEP padding warning for cleaner test output
        warnings.filterwarnings('ignore', category=UserWarning)

    def tearDown(self):
        # Clean up after each test.
        keypairs.clear()

    # Health Check Tests

    def test_health_check(self):
        # Test health check endpoint.
        response = self.app.get('/api/health')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['status'], 'ok')
        self.assertIn('message', data)

    # Key Generation Tests

    def test_generate_keys_256_bit(self):
        # Test generating 256-bit RSA keys.
        response = self.app.post(
            '/api/generate-keys',
            data=json.dumps({'size': 256, 'session_id': 'test1'}),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data['success'])
        self.assertEqual(data['size'], 256)
        self.assertIn('public_key', data)
        self.assertIn('private_key', data)

    def test_generate_keys_512_bit(self):
        # Test generating 512-bit RSA keys.
        response = self.app.post(
            '/api/generate-keys',
            data=json.dumps({'size': 512, 'session_id': 'test2'}),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data['success'])
        self.assertEqual(data['size'], 512)

    def test_generate_keys_1024_bit(self):
        # Test generating 1024-bit RSA keys.
        response = self.app.post(
            '/api/generate-keys',
            data=json.dumps({'size': 1024, 'session_id': 'test3'}),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data['success'])
        self.assertEqual(data['size'], 1024)

    def test_generate_keys_2048_bit(self):
        # Test generating 2048-bit RSA keys.
        response = self.app.post(
            '/api/generate-keys',
            data=json.dumps({'size': 2048, 'session_id': 'test4'}),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data['success'])
        self.assertEqual(data['size'], 2048)

    def test_generate_keys_default_size(self):
        # Test generating keys with default size (512-bit).
        response = self.app.post(
            '/api/generate-keys',
            data=json.dumps({'session_id': 'test5'}),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data['success'])
        self.assertEqual(data['size'], 512)

    def test_generate_keys_invalid_size(self):
        # Test generating keys with invalid size.
        response = self.app.post(
            '/api/generate-keys',
            data=json.dumps({'size': 128, 'session_id': 'test6'}),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertFalse(data['success'])
        self.assertIn('error', data)

    def test_generate_keys_multiple_sessions(self):
        # Test generating keys for multiple sessions.
        # Generate keys for session 1
        response1 = self.app.post(
            '/api/generate-keys',
            data=json.dumps({'size': 512, 'session_id': 'session1'}),
            content_type='application/json'
        )
        self.assertEqual(response1.status_code, 200)

        # Generate keys for session 2
        response2 = self.app.post(
            '/api/generate-keys',
            data=json.dumps({'size': 512, 'session_id': 'session2'}),
            content_type='application/json'
        )
        self.assertEqual(response2.status_code, 200)

        # Verify both sessions have different keys
        data1 = json.loads(response1.data)
        data2 = json.loads(response2.data)
        self.assertNotEqual(data1['public_key']['n'], data2['public_key']['n'])

    # Encryption/Decryption Tests 

    def test_encrypt_decrypt_basic(self):
        # Test basic encryption and decryption.
        # Generate keys
        self.app.post(
            '/api/generate-keys',
            data=json.dumps({'size': 512, 'session_id': 'test_enc'}),
            content_type='application/json'
        )

        # Encrypt message
        message = "Hello, World!"
        enc_response = self.app.post(
            '/api/encrypt',
            data=json.dumps({'message': message, 'session_id': 'test_enc'}),
            content_type='application/json'
        )
        self.assertEqual(enc_response.status_code, 200)
        enc_data = json.loads(enc_response.data)
        self.assertTrue(enc_data['success'])
        ciphertext = enc_data['ciphertext']

        # Decrypt message
        dec_response = self.app.post(
            '/api/decrypt',
            data=json.dumps({'ciphertext': ciphertext, 'session_id': 'test_enc'}),
            content_type='application/json'
        )
        self.assertEqual(dec_response.status_code, 200)
        dec_data = json.loads(dec_response.data)
        self.assertTrue(dec_data['success'])
        self.assertEqual(dec_data['plaintext'], message)

    def test_encrypt_empty_message(self):
        # Test encrypting an empty message.
        # Generate keys
        self.app.post(
            '/api/generate-keys',
            data=json.dumps({'size': 512, 'session_id': 'test_empty'}),
            content_type='application/json'
        )

        # Try to encrypt empty message
        response = self.app.post(
            '/api/encrypt',
            data=json.dumps({'message': '', 'session_id': 'test_empty'}),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertFalse(data['success'])

    def test_encrypt_without_keys(self):
        # Test encrypting without generating keys first.
        response = self.app.post(
            '/api/encrypt',
            data=json.dumps({'message': 'Test', 'session_id': 'no_keys'}),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertFalse(data['success'])
        self.assertIn('No keys found', data['error'])

    def test_decrypt_empty_ciphertext(self):
        # Test decrypting an empty ciphertext.
        # Generate keys
        self.app.post(
            '/api/generate-keys',
            data=json.dumps({'size': 512, 'session_id': 'test_dec_empty'}),
            content_type='application/json'
        )

        # Try to decrypt empty ciphertext
        response = self.app.post(
            '/api/decrypt',
            data=json.dumps({'ciphertext': '', 'session_id': 'test_dec_empty'}),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertFalse(data['success'])

    def test_encrypt_unicode_message(self):
        # Test encrypting and decrypting Unicode messages.
        # Generate keys
        self.app.post(
            '/api/generate-keys',
            data=json.dumps({'size': 512, 'session_id': 'test_unicode'}),
            content_type='application/json'
        )

        # Test with Unicode characters
        message = "Hello 世界 🌍"
        enc_response = self.app.post(
            '/api/encrypt',
            data=json.dumps({'message': message, 'session_id': 'test_unicode'}),
            content_type='application/json'
        )
        self.assertEqual(enc_response.status_code, 200)
        enc_data = json.loads(enc_response.data)
        ciphertext = enc_data['ciphertext']

        # Decrypt
        dec_response = self.app.post(
            '/api/decrypt',
            data=json.dumps({'ciphertext': ciphertext, 'session_id': 'test_unicode'}),
            content_type='application/json'
        )
        dec_data = json.loads(dec_response.data)
        self.assertEqual(dec_data['plaintext'], message)

    # Digital Signature Tests 

    def test_sign_verify_basic(self):
        # Test basic digital signature and verification.
        # Generate keys
        self.app.post(
            '/api/generate-keys',
            data=json.dumps({'size': 512, 'session_id': 'test_sig'}),
            content_type='application/json'
        )

        # Sign message
        message = "Important document"
        sign_response = self.app.post(
            '/api/sign',
            data=json.dumps({'message': message, 'session_id': 'test_sig'}),
            content_type='application/json'
        )
        self.assertEqual(sign_response.status_code, 200)
        sign_data = json.loads(sign_response.data)
        self.assertTrue(sign_data['success'])

        # Verify signature
        verify_response = self.app.post(
            '/api/verify',
            data=json.dumps({
                'message': message,
                'signature': sign_data['signature'],
                'message_hash': sign_data['message_hash'],
                'session_id': 'test_sig'
            }),
            content_type='application/json'
        )
        self.assertEqual(verify_response.status_code, 200)
        verify_data = json.loads(verify_response.data)
        self.assertTrue(verify_data['success'])
        self.assertTrue(verify_data['valid'])

    def test_verify_invalid_signature(self):
        # Test verifying an invalid signature.
        # Generate keys
        self.app.post(
            '/api/generate-keys',
            data=json.dumps({'size': 512, 'session_id': 'test_invalid_sig'}),
            content_type='application/json'
        )

        # Sign message
        message = "Original message"
        sign_response = self.app.post(
            '/api/sign',
            data=json.dumps({'message': message, 'session_id': 'test_invalid_sig'}),
            content_type='application/json'
        )
        sign_data = json.loads(sign_response.data)

        # Sign a different message to get a different hash
        modified_sign_response = self.app.post(
            '/api/sign',
            data=json.dumps({'message': 'Modified message', 'session_id': 'test_invalid_sig'}),
            content_type='application/json'
        )
        modified_sign_data = json.loads(modified_sign_response.data)

        # Verify original signature with modified message hash (should fail)
        verify_response = self.app.post(
            '/api/verify',
            data=json.dumps({
                'message': 'Modified message',
                'signature': sign_data['signature'],  # Original signature
                'message_hash': modified_sign_data['message_hash'],  # Modified hash
                'session_id': 'test_invalid_sig'
            }),
            content_type='application/json'
        )
        verify_data = json.loads(verify_response.data)
        self.assertTrue(verify_data['success'])
        self.assertFalse(verify_data['valid'])

    def test_sign_empty_message(self):
        # Test signing an empty message.
        # Generate keys
        self.app.post(
            '/api/generate-keys',
            data=json.dumps({'size': 512, 'session_id': 'test_sign_empty'}),
            content_type='application/json'
        )

        # Try to sign empty message
        response = self.app.post(
            '/api/sign',
            data=json.dumps({'message': '', 'session_id': 'test_sign_empty'}),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertFalse(data['success'])

    def test_verify_missing_fields(self):
        # Test verification with missing required fields.
        # Generate keys
        self.app.post(
            '/api/generate-keys',
            data=json.dumps({'size': 512, 'session_id': 'test_verify_missing'}),
            content_type='application/json'
        )

        # Try to verify without signature
        response = self.app.post(
            '/api/verify',
            data=json.dumps({
                'message': 'Test',
                'session_id': 'test_verify_missing'
            }),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertFalse(data['success'])
        self.assertIn('Missing required fields', data['error'])

    # Get Keys Tests

    def test_get_keys_exists(self):
        # Test getting existing keys.
        # Generate keys
        self.app.post(
            '/api/generate-keys',
            data=json.dumps({'size': 512, 'session_id': 'test_get_keys'}),
            content_type='application/json'
        )

        # Get keys
        response = self.app.post(
            '/api/get-keys',
            data=json.dumps({'session_id': 'test_get_keys'}),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data['success'])
        self.assertTrue(data['has_keys'])
        self.assertIn('public_key', data)
        self.assertIn('private_key', data)

    def test_get_keys_not_exists(self):
        # Test getting keys that don't exist.
        response = self.app.post(
            '/api/get-keys',
            data=json.dumps({'session_id': 'nonexistent'}),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data['success'])
        self.assertFalse(data['has_keys'])

    # Example Endpoint Tests

    def test_example_endpoint(self):
        # Test the example endpoint.
        response = self.app.get('/api/example')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('description', data)
        self.assertIn('examples', data)
        self.assertIsInstance(data['examples'], list)

    # Integration Tests 

    def test_complete_workflow(self):
        # Test complete workflow: generate keys, encrypt, decrypt, sign, verify.
        session_id = 'complete_workflow'

        # 1. Generate keys
        gen_response = self.app.post(
            '/api/generate-keys',
            data=json.dumps({'size': 512, 'session_id': session_id}),
            content_type='application/json'
        )
        self.assertEqual(gen_response.status_code, 200)

        # 2. Encrypt message
        message = "Test message for complete workflow"
        enc_response = self.app.post(
            '/api/encrypt',
            data=json.dumps({'message': message, 'session_id': session_id}),
            content_type='application/json'
        )
        enc_data = json.loads(enc_response.data)
        self.assertTrue(enc_data['success'])

        # 3. Decrypt message
        dec_response = self.app.post(
            '/api/decrypt',
            data=json.dumps({'ciphertext': enc_data['ciphertext'], 'session_id': session_id}),
            content_type='application/json'
        )
        dec_data = json.loads(dec_response.data)
        self.assertTrue(dec_data['success'])
        self.assertEqual(dec_data['plaintext'], message)

        # 4. Sign message
        sign_response = self.app.post(
            '/api/sign',
            data=json.dumps({'message': message, 'session_id': session_id}),
            content_type='application/json'
        )
        sign_data = json.loads(sign_response.data)
        self.assertTrue(sign_data['success'])

        # 5. Verify signature
        verify_response = self.app.post(
            '/api/verify',
            data=json.dumps({
                'message': message,
                'signature': sign_data['signature'],
                'message_hash': sign_data['message_hash'],
                'session_id': session_id
            }),
            content_type='application/json'
        )
        verify_data = json.loads(verify_response.data)
        self.assertTrue(verify_data['success'])
        self.assertTrue(verify_data['valid'])


def run_api_tests():
    # Run all Flask API tests and display results.
    print("=" * 70)
    print("Flask RSA API Unit Tests")
    print("CSCI 663 - Introduction to Cryptography")
    print("=" * 70)
    print()

    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add all test cases
    suite.addTests(loader.loadTestsFromTestCase(TestFlaskRSAAPI))

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Print summary
    print("\n" + "=" * 70)
    print("API Test Summary")
    print("=" * 70)
    print(f"Tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")

    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_api_tests()
    sys.exit(0 if success else 1)
