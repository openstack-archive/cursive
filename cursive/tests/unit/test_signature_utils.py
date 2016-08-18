#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import base64
import datetime
import mock
import os
import shutil
import tempfile

from castellan.common.exception import KeyManagerError
import cryptography.exceptions as crypto_exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from oslo_utils import timeutils

from cursive import exception
from cursive import signature_utils
from cursive.tests import base

TEST_RSA_PRIVATE_KEY = rsa.generate_private_key(public_exponent=3,
                                                key_size=1024,
                                                backend=default_backend())

# secp521r1 is assumed to be available on all supported platforms
TEST_ECC_PRIVATE_KEY = ec.generate_private_key(ec.SECP521R1(),
                                               default_backend())

TEST_DSA_PRIVATE_KEY = dsa.generate_private_key(key_size=3072,
                                                backend=default_backend())

# Required image property names
(SIGNATURE, HASH_METHOD, KEY_TYPE, CERT_UUID) = (
    signature_utils.SIGNATURE,
    signature_utils.HASH_METHOD,
    signature_utils.KEY_TYPE,
    signature_utils.CERT_UUID
)


class FakeKeyManager(object):

    def __init__(self):
        self.certs = {'invalid_format_cert':
                      FakeCastellanCertificate('A' * 256, 'BLAH'),
                      'valid_format_cert':
                      FakeCastellanCertificate('A' * 256, 'X.509')}

    def get(self, context, cert_uuid):
        cert = self.certs.get(cert_uuid)

        if cert is None:
            raise KeyManagerError("No matching certificate found.")

        return cert


class FakeCastellanCertificate(object):

    def __init__(self, data, cert_format):
        self.data = data
        self.cert_format = cert_format

    @property
    def format(self):
        return self.cert_format

    def get_encoded(self):
        return self.data


class FakeCryptoCertificate(object):

    def __init__(self, pub_key=TEST_RSA_PRIVATE_KEY.public_key(),
                 not_valid_before=(timeutils.utcnow() -
                                   datetime.timedelta(hours=1)),
                 not_valid_after=(timeutils.utcnow() +
                                  datetime.timedelta(hours=2))):
        self.pub_key = pub_key
        self.cert_not_valid_before = not_valid_before
        self.cert_not_valid_after = not_valid_after

    def public_key(self):
        return self.pub_key

    @property
    def not_valid_before(self):
        return self.cert_not_valid_before

    @property
    def not_valid_after(self):
        return self.cert_not_valid_after


class BadPublicKey(object):

    def verifier(self, signature, padding, hash_method):
        return None


class TestSignatureUtils(base.TestCase):
    """Test methods of signature_utils"""

    def setUp(self):
        super(TestSignatureUtils, self).setUp()

        self.cert_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            'data'
        )
        self.temp_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.temp_dir)
        certs = [
            'self_signed_cert.pem',
            'self_signed_cert.der'
        ]
        for cert in certs:
            shutil.copyfile(
                os.path.join(self.cert_path, cert),
                os.path.join(self.temp_dir, cert)
            )

    def tearDown(self):
        super(TestSignatureUtils, self).tearDown()

    def test_should_create_verifier(self):
        image_props = {CERT_UUID: 'CERT_UUID',
                       HASH_METHOD: 'HASH_METHOD',
                       SIGNATURE: 'SIGNATURE',
                       KEY_TYPE: 'SIG_KEY_TYPE'}
        self.assertTrue(signature_utils.should_create_verifier(image_props))

    def test_should_create_verifier_fail(self):
        bad_image_properties = [{CERT_UUID: 'CERT_UUID',
                                 HASH_METHOD: 'HASH_METHOD',
                                 SIGNATURE: 'SIGNATURE'},
                                {CERT_UUID: 'CERT_UUID',
                                 HASH_METHOD: 'HASH_METHOD',
                                 KEY_TYPE: 'SIG_KEY_TYPE'},
                                {CERT_UUID: 'CERT_UUID',
                                 SIGNATURE: 'SIGNATURE',
                                 KEY_TYPE: 'SIG_KEY_TYPE'},
                                {HASH_METHOD: 'HASH_METHOD',
                                 SIGNATURE: 'SIGNATURE',
                                 KEY_TYPE: 'SIG_KEY_TYPE'}]

        for bad_props in bad_image_properties:
            result = signature_utils.should_create_verifier(bad_props)
            self.assertFalse(result)

    @mock.patch('cursive.signature_utils.get_public_key')
    def test_verify_signature_PSS(self, mock_get_pub_key):
        data = b'224626ae19824466f2a7f39ab7b80f7f'
        mock_get_pub_key.return_value = TEST_RSA_PRIVATE_KEY.public_key()
        for hash_name, hash_alg in signature_utils.HASH_METHODS.items():
            signer = TEST_RSA_PRIVATE_KEY.signer(
                padding.PSS(
                    mgf=padding.MGF1(hash_alg),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hash_alg
            )
            signer.update(data)
            signature = base64.b64encode(signer.finalize())
            img_sig_cert_uuid = 'fea14bc2-d75f-4ba5-bccc-b5c924ad0693'
            verifier = signature_utils.get_verifier(None, img_sig_cert_uuid,
                                                    hash_name, signature,
                                                    signature_utils.RSA_PSS)
            verifier.update(data)
            verifier.verify()

    @mock.patch('cursive.signature_utils.get_public_key')
    def test_verify_signature_ECC(self, mock_get_pub_key):
        data = b'224626ae19824466f2a7f39ab7b80f7f'
        # test every ECC curve
        for curve in signature_utils.ECC_CURVES:
            key_type_name = 'ECC_' + curve.name.upper()
            try:
                signature_utils.SignatureKeyType.lookup(key_type_name)
            except exception.SignatureVerificationError:
                import warnings
                warnings.warn("ECC curve '%s' not supported" % curve.name)
                continue

            # Create a private key to use
            private_key = ec.generate_private_key(curve,
                                                  default_backend())
            mock_get_pub_key.return_value = private_key.public_key()
            for hash_name, hash_alg in signature_utils.HASH_METHODS.items():
                signer = private_key.signer(
                    ec.ECDSA(hash_alg)
                )
                signer.update(data)
                signature = base64.b64encode(signer.finalize())
                img_sig_cert_uuid = 'fea14bc2-d75f-4ba5-bccc-b5c924ad0693'
                verifier = signature_utils.get_verifier(None,
                                                        img_sig_cert_uuid,
                                                        hash_name, signature,
                                                        key_type_name)
                verifier.update(data)
                verifier.verify()

    @mock.patch('cursive.signature_utils.get_public_key')
    def test_verify_signature_DSA(self, mock_get_pub_key):
        data = b'224626ae19824466f2a7f39ab7b80f7f'
        mock_get_pub_key.return_value = TEST_DSA_PRIVATE_KEY.public_key()
        for hash_name, hash_alg in signature_utils.HASH_METHODS.items():
            signer = TEST_DSA_PRIVATE_KEY.signer(
                hash_alg
            )
            signer.update(data)
            signature = base64.b64encode(signer.finalize())
            img_sig_cert_uuid = 'fea14bc2-d75f-4ba5-bccc-b5c924ad0693'
            verifier = signature_utils.get_verifier(None, img_sig_cert_uuid,
                                                    hash_name, signature,
                                                    signature_utils.DSA)
            verifier.update(data)
            verifier.verify()

    @mock.patch('cursive.signature_utils.get_public_key')
    def test_verify_signature_bad_signature(self, mock_get_pub_key):
        data = b'224626ae19824466f2a7f39ab7b80f7f'
        mock_get_pub_key.return_value = TEST_RSA_PRIVATE_KEY.public_key()
        img_sig_cert_uuid = 'fea14bc2-d75f-4ba5-bccc-b5c924ad0693'
        verifier = signature_utils.get_verifier(None, img_sig_cert_uuid,
                                                'SHA-256', 'BLAH',
                                                signature_utils.RSA_PSS)
        verifier.update(data)
        self.assertRaises(crypto_exceptions.InvalidSignature,
                          verifier.verify)

    def test_get_verifier_invalid_image_props(self):
        self.assertRaisesRegex(exception.SignatureVerificationError,
                               'Required image properties for signature'
                               ' verification do not exist. Cannot verify'
                               ' signature. Missing property: .*',
                               signature_utils.get_verifier,
                               None, None, 'SHA-256', 'BLAH',
                               signature_utils.RSA_PSS)

    @mock.patch('cursive.signature_utils.get_public_key')
    def test_verify_signature_bad_sig_key_type(self, mock_get_pub_key):
        mock_get_pub_key.return_value = TEST_RSA_PRIVATE_KEY.public_key()
        img_sig_cert_uuid = 'fea14bc2-d75f-4ba5-bccc-b5c924ad0693'
        self.assertRaisesRegex(exception.SignatureVerificationError,
                               'Invalid signature key type: .*',
                               signature_utils.get_verifier,
                               None, img_sig_cert_uuid, 'SHA-256',
                               'BLAH', 'BLAH')

    @mock.patch('cursive.signature_utils.get_public_key')
    def test_get_verifier_none(self, mock_get_pub_key):
        mock_get_pub_key.return_value = BadPublicKey()
        img_sig_cert_uuid = 'fea14bc2-d75f-4ba5-bccc-b5c924ad0693'
        self.assertRaisesRegex(exception.SignatureVerificationError,
                               'Error occurred while creating'
                               ' the verifier',
                               signature_utils.get_verifier,
                               None, img_sig_cert_uuid, 'SHA-256',
                               'BLAH', signature_utils.RSA_PSS)

    def test_get_signature(self):
        signature = b'A' * 256
        data = base64.b64encode(signature)
        self.assertEqual(signature,
                         signature_utils.get_signature(data))

    def test_get_signature_fail(self):
        self.assertRaisesRegex(exception.SignatureVerificationError,
                               'The signature data was not properly'
                               ' encoded using base64',
                               signature_utils.get_signature, '///')

    def test_get_hash_method(self):
        hash_dict = signature_utils.HASH_METHODS
        for hash_name in hash_dict.keys():
            hash_class = signature_utils.get_hash_method(hash_name).__class__
            self.assertIsInstance(hash_dict[hash_name], hash_class)

    def test_get_hash_method_fail(self):
        self.assertRaisesRegex(exception.SignatureVerificationError,
                               'Invalid signature hash method: .*',
                               signature_utils.get_hash_method, 'SHA-2')

    def test_signature_key_type_lookup(self):
        for sig_format in [signature_utils.RSA_PSS, signature_utils.DSA]:
            sig_key_type = signature_utils.SignatureKeyType.lookup(sig_format)
            self.assertIsInstance(sig_key_type,
                                  signature_utils.SignatureKeyType)
            self.assertEqual(sig_format, sig_key_type.name)

    def test_signature_key_type_lookup_fail(self):
        self.assertRaisesRegex(exception.SignatureVerificationError,
                               'Invalid signature key type: .*',
                               signature_utils.SignatureKeyType.lookup,
                               'RSB-PSS')

    @mock.patch('cursive.signature_utils.get_certificate')
    @mock.patch('cursive.signature_utils.verify_certificate')
    def test_get_public_key_rsa(self, mock_verify_cert, mock_get_cert):
        fake_cert = FakeCryptoCertificate()
        mock_get_cert.return_value = fake_cert
        sig_key_type = signature_utils.SignatureKeyType.lookup(
            signature_utils.RSA_PSS
        )
        result_pub_key = signature_utils.get_public_key(None, None,
                                                        sig_key_type)
        self.assertEqual(fake_cert.public_key(), result_pub_key)

    @mock.patch('cursive.signature_utils.get_certificate')
    @mock.patch('cursive.signature_utils.verify_certificate')
    def test_get_public_key_ecc(self, mock_verify_cert, mock_get_cert):
        fake_cert = FakeCryptoCertificate(TEST_ECC_PRIVATE_KEY.public_key())
        mock_get_cert.return_value = fake_cert
        sig_key_type = signature_utils.SignatureKeyType.lookup('ECC_SECP521R1')
        result_pub_key = signature_utils.get_public_key(None, None,
                                                        sig_key_type)
        self.assertEqual(fake_cert.public_key(), result_pub_key)

    @mock.patch('cursive.signature_utils.get_certificate')
    @mock.patch('cursive.signature_utils.verify_certificate')
    def test_get_public_key_dsa(self, mock_verify_cert, mock_get_cert):
        fake_cert = FakeCryptoCertificate(TEST_DSA_PRIVATE_KEY.public_key())
        mock_get_cert.return_value = fake_cert
        sig_key_type = signature_utils.SignatureKeyType.lookup(
            signature_utils.DSA
        )
        result_pub_key = signature_utils.get_public_key(None, None,
                                                        sig_key_type)
        self.assertEqual(fake_cert.public_key(), result_pub_key)

    @mock.patch('cursive.signature_utils.get_certificate')
    @mock.patch('cursive.signature_utils.verify_certificate')
    def test_get_public_key_invalid_key(self, mock_verify_certificate,
                                        mock_get_certificate):
        bad_pub_key = 'A' * 256
        mock_get_certificate.return_value = FakeCryptoCertificate(bad_pub_key)
        sig_key_type = signature_utils.SignatureKeyType.lookup(
            signature_utils.RSA_PSS
        )
        self.assertRaisesRegex(exception.SignatureVerificationError,
                               'Invalid public key type for '
                               'signature key type: .*',
                               signature_utils.get_public_key, None,
                               None, sig_key_type)

    @mock.patch('cryptography.x509.load_der_x509_certificate')
    @mock.patch('castellan.key_manager.API', return_value=FakeKeyManager())
    def test_get_certificate(self, mock_key_manager_API, mock_load_cert):
        cert_uuid = 'valid_format_cert'
        x509_cert = FakeCryptoCertificate()
        mock_load_cert.return_value = x509_cert
        self.assertEqual(x509_cert,
                         signature_utils.get_certificate(None, cert_uuid))

    @mock.patch('castellan.key_manager.API', return_value=FakeKeyManager())
    def test_get_certificate_key_manager_fail(self, mock_key_manager_API):
        bad_cert_uuid = 'fea14bc2-d75f-4ba5-bccc-b5c924ad0695'
        self.assertRaisesRegex(exception.SignatureVerificationError,
                               'Unable to retrieve certificate with ID: .*',
                               signature_utils.get_certificate, None,
                               bad_cert_uuid)

    @mock.patch('castellan.key_manager.API', return_value=FakeKeyManager())
    def test_get_certificate_invalid_format(self, mock_API):
        cert_uuid = 'invalid_format_cert'
        self.assertRaisesRegex(exception.SignatureVerificationError,
                               'Invalid certificate format: .*',
                               signature_utils.get_certificate, None,
                               cert_uuid)


class TestCertificateValidation(base.TestCase):
    """Test methods for the certificate verification context and utilities"""

    def setUp(self):
        super(TestCertificateValidation, self).setUp()

        self.cert_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            'data'
        )
        self.temp_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.temp_dir)
        certs = [
            'self_signed_cert.pem',
            'self_signed_cert.der'
        ]
        for cert in certs:
            shutil.copyfile(
                os.path.join(self.cert_path, cert),
                os.path.join(self.temp_dir, cert)
            )

    def tearDown(self):
        super(TestCertificateValidation, self).tearDown()

    def test_load_PEM_certificate(self):
        # Test loading a PEM-encoded certificate
        cert = signature_utils.load_certificate(
            os.path.join(self.temp_dir, 'self_signed_cert.pem')
        )
        self.assertIsInstance(cert, x509.Certificate)

    def test_load_DER_certificate(self):
        # Test loading a DER-encoded certificate
        cert = signature_utils.load_certificate(
            os.path.join(self.temp_dir, 'self_signed_cert.der')
        )
        self.assertIsInstance(cert, x509.Certificate)

    def test_load_invalid_certificate(self):
        # Test loading a non-certificate file
        path = os.path.join(self.cert_path, 'not_a_cert.txt')
        self.assertRaisesRegex(
            exception.SignatureVerificationError,
            "Failed to load certificate: %s" % path,
            signature_utils.load_certificate,
            path
        )

    def test_load_valid_certificates_from_valid_trust_store(self):
        # Test loading certificates from a valid certificate directory
        cert_tuples = signature_utils.load_certificates_from_trust_store(
            self.temp_dir
        )
        self.assertIsInstance(cert_tuples, list)
        self.assertEqual(2, len(cert_tuples))
        for t in cert_tuples:
            self.assertEqual(2, len(t))
            path, cert = t
            self.assertEqual(True, os.path.isfile(path))
            self.assertIsInstance(cert, x509.Certificate)

    @mock.patch('cursive.signature_utils.LOG')
    def test_load_invalid_certificate_from_valid_trust_store(self, mock_log):
        # Test loading an invalid certificate from a valid directory
        temp_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, temp_dir)
        shutil.copyfile(
            os.path.join(self.cert_path, 'not_a_cert.txt'),
            os.path.join(temp_dir, 'not_a_cert.txt')
        )
        cert_tuples = signature_utils.load_certificates_from_trust_store(
            temp_dir
        )
        self.assertEqual(1, mock_log.warning.call_count)
        self.assertIsInstance(cert_tuples, list)
        self.assertEqual(0, len(cert_tuples))

    def test_load_certificates_from_empty_trust_store(self):
        # Test loading certificates from an empty valid directory
        temp_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, temp_dir)
        cert_tuples = signature_utils.load_certificates_from_trust_store(
            temp_dir
        )
        self.assertEqual(0, len(cert_tuples))

    def test_load_certificates_from_invalid_trust_store(self):
        # Test loading certificates from an invalid directory
        self.assertRaisesRegex(
            exception.SignatureVerificationError,
            "The path to the certificate trust store is required.",
            signature_utils.load_certificates_from_trust_store,
            'invalid-path'
        )

    @mock.patch('oslo_utils.timeutils.utcnow')
    def test_is_within_valid_dates(self, mock_utcnow):
        # Verify a certificate is valid at a time within its valid date range
        cert = signature_utils.load_certificate(
            os.path.join(self.temp_dir, 'self_signed_cert.pem')
        )
        mock_utcnow.return_value = datetime.datetime(2017, 1, 1)
        result = signature_utils.is_within_valid_dates(cert)
        self.assertEqual(True, result)

    @mock.patch('oslo_utils.timeutils.utcnow')
    def test_is_before_valid_dates(self, mock_utcnow):
        # Verify a certificate is invalid at a time before its valid date range
        cert = signature_utils.load_certificate(
            os.path.join(self.temp_dir, 'self_signed_cert.pem')
        )
        mock_utcnow.return_value = datetime.datetime(2000, 1, 1)
        result = signature_utils.is_within_valid_dates(cert)
        self.assertEqual(False, result)

    @mock.patch('oslo_utils.timeutils.utcnow')
    def test_is_after_valid_dates(self, mock_utcnow):
        # Verify a certificate is invalid at a time after its valid date range
        cert = signature_utils.load_certificate(
            os.path.join(self.temp_dir, 'self_signed_cert.pem')
        )
        mock_utcnow.return_value = datetime.datetime(2100, 1, 1)
        result = signature_utils.is_within_valid_dates(cert)
        self.assertEqual(False, result)

    def test_is_issuer(self):
        # Test issuer and subject name matching for a self-signed certificate.
        cert = signature_utils.load_certificate(
            os.path.join(self.temp_dir, 'self_signed_cert.pem')
        )
        result = signature_utils.is_issuer(cert, cert)
        self.assertEqual(True, result)

    def test_is_not_issuer(self):
        # Test issuer and subject name mismatching.
        cert = signature_utils.load_certificate(
            os.path.join(self.temp_dir, 'self_signed_cert.pem')
        )
        alt = signature_utils.load_certificate(
            os.path.join(self.cert_path, 'orphaned_cert.pem')
        )
        result = signature_utils.is_issuer(cert, alt)
        self.assertEqual(False, result)

    def test_can_sign_certificates(self):
        # Test that a well-formatted certificate can sign
        cert = signature_utils.load_certificate(
            os.path.join(self.temp_dir, 'self_signed_cert.pem')
        )
        result = signature_utils.can_sign_certificates(cert)
        self.assertEqual(True, result)

    def test_cannot_sign_certificates_without_basic_constraints(self):
        # Verify a certificate without basic constraints cannot sign
        cert = signature_utils.load_certificate(
            os.path.join(
                self.cert_path,
                'self_signed_cert_missing_ca_constraint.pem'
            )
        )
        result = signature_utils.can_sign_certificates(cert)
        self.assertEqual(False, result)

    def test_cannot_sign_certificates_with_invalid_basic_constraints(self):
        # Verify a certificate with invalid basic constraints cannot sign
        cert = signature_utils.load_certificate(
            os.path.join(
                self.cert_path,
                'self_signed_cert_invalid_ca_constraint.pem'
            )
        )
        result = signature_utils.can_sign_certificates(cert)
        self.assertEqual(False, result)

    def test_cannot_sign_certificates_without_key_usage(self):
        # Verify a certificate without key usage cannot sign
        cert = signature_utils.load_certificate(
            os.path.join(
                self.cert_path,
                'self_signed_cert_missing_key_usage.pem'
            )
        )
        result = signature_utils.can_sign_certificates(cert)
        self.assertEqual(False, result)

    def test_cannot_sign_certificates_with_invalid_key_usage(self):
        # Verify a certificate with invalid key usage cannot sign
        cert = signature_utils.load_certificate(
            os.path.join(
                self.cert_path,
                'self_signed_cert_invalid_key_usage.pem'
            )
        )
        result = signature_utils.can_sign_certificates(cert)
        self.assertEqual(False, result)

    def test_verify_signing_certificate(self):
        signing_certificate = signature_utils.load_certificate(
            os.path.join(self.cert_path, 'self_signed_cert.pem')
        )
        signed_certificate = signature_utils.load_certificate(
            os.path.join(self.cert_path, 'signed_cert.pem')
        )

        signature_utils.verify_certificate_signature(
            signing_certificate,
            signed_certificate
        )

    def test_verify_valid_certificate(self):
        # Test verifying a valid certificate
        cert = signature_utils.load_certificate(
            os.path.join(self.cert_path, 'signed_cert.pem')
        )
        signature_utils.verify_certificate(cert, self.temp_dir)

    def test_verify_invalid_certificate(self):
        # Test verifying an invalid certificate
        cert = signature_utils.load_certificate(
            os.path.join(self.cert_path, 'orphaned_cert.pem')
        )
        self.assertRaisesRegex(
            exception.SignatureVerificationError,
            "Certificate chain building failed. Could not locate the "
            "next signing certificate in the certificate trust store.",
            signature_utils.verify_certificate,
            cert,
            self.temp_dir
        )

    def test_verify_valid_certificate_with_empty_trust_store(self):
        # Test verifying a valid certificate against an empty trust store
        cert = signature_utils.load_certificate(
            os.path.join(self.cert_path, 'signed_cert.pem')
        )
        self.assertRaisesRegex(
            exception.SignatureVerificationError,
            "Certificate chain building failed. Could not locate the "
            "next signing certificate in the certificate trust store.",
            signature_utils.verify_certificate,
            cert,
            ''
        )

        self.assertRaisesRegex(
            exception.SignatureVerificationError,
            "Certificate chain building failed. Could not locate the "
            "next signing certificate in the certificate trust store.",
            signature_utils.verify_certificate,
            cert,
            None
        )

    @mock.patch('oslo_utils.timeutils.utcnow')
    def test_context_init(self, mock_utcnow):
        # Test constructing a context object with a valid set of certificates
        mock_utcnow.return_value = datetime.datetime(2017, 1, 1)
        cert_tuples = signature_utils.load_certificates_from_trust_store(
            self.temp_dir
        )
        context = signature_utils.CertificateVerificationContext(cert_tuples)
        self.assertEqual(2, len(context._signing_certificates))
        for t in cert_tuples:
            path, cert = t
            self.assertIn(cert, context._signing_certificates)

    @mock.patch('cursive.signature_utils.LOG')
    @mock.patch('oslo_utils.timeutils.utcnow')
    def test_context_init_with_invalid_certificate(self, mock_utcnow,
                                                   mock_log):
        # Test constructing a context object with an invalid certificate
        mock_utcnow.return_value = datetime.datetime(2017, 1, 1)
        alt_cert_tuples = [('path', None)]
        context = signature_utils.CertificateVerificationContext(
            alt_cert_tuples
        )
        self.assertEqual(0, len(context._signing_certificates))
        self.assertEqual(1, mock_log.error.call_count)

    @mock.patch('cursive.signature_utils.LOG')
    @mock.patch('oslo_utils.timeutils.utcnow')
    def test_context_init_with_non_signing_certificate(self, mock_utcnow,
                                                       mock_log):
        # Test constructing a context object with an non-signing certificate
        mock_utcnow.return_value = datetime.datetime(2017, 1, 1)
        non_signing_cert = signature_utils.load_certificate(
            os.path.join(
                self.cert_path,
                'self_signed_cert_missing_key_usage.pem'
            )
        )
        alt_cert_tuples = [('path', non_signing_cert)]
        context = signature_utils.CertificateVerificationContext(
            alt_cert_tuples
        )
        self.assertEqual(0, len(context._signing_certificates))
        self.assertEqual(1, mock_log.warning.call_count)

    @mock.patch('cursive.signature_utils.LOG')
    @mock.patch('oslo_utils.timeutils.utcnow')
    def test_context_init_with_out_of_date_certificate(self, mock_utcnow,
                                                       mock_log):
        # Test constructing a context object with out-of-date certificates
        mock_utcnow.return_value = datetime.datetime(2100, 1, 1)
        cert_tuples = signature_utils.load_certificates_from_trust_store(
            self.temp_dir
        )
        context = signature_utils.CertificateVerificationContext(cert_tuples)
        self.assertEqual(0, len(context._signing_certificates))
        self.assertEqual(2, mock_log.warning.call_count)

    @mock.patch('oslo_utils.timeutils.utcnow')
    def test_context_update_with_valid_certificate(self, mock_utcnow):
        # Test updating the context with a valid certificate
        mock_utcnow.return_value = datetime.datetime(2017, 1, 1)
        cert_tuples = signature_utils.load_certificates_from_trust_store(
            self.temp_dir
        )
        context = signature_utils.CertificateVerificationContext(cert_tuples)
        cert = signature_utils.load_certificate(
            os.path.join(self.cert_path, 'orphaned_cert.pem')
        )
        context.update(cert)
        self.assertEqual(cert, context._signed_certificate)

    @mock.patch('oslo_utils.timeutils.utcnow')
    def test_context_update_with_date_invalid_certificate(self, mock_utcnow):
        # Test updating the context with an out-of-date certificate
        mock_utcnow.return_value = datetime.datetime(2017, 1, 1)
        cert_tuples = signature_utils.load_certificates_from_trust_store(
            self.temp_dir
        )
        context = signature_utils.CertificateVerificationContext(cert_tuples)
        cert = signature_utils.load_certificate(
            os.path.join(self.cert_path, 'orphaned_cert.pem')
        )
        mock_utcnow.return_value = datetime.datetime(2100, 1, 1)
        self.assertRaisesRegex(
            exception.SignatureVerificationError,
            "The certificate is outside its valid date range.",
            context.update,
            cert
        )

    def test_context_update_with_invalid_certificate(self):
        # Test updating the context with an invalid certificate
        cert_tuples = signature_utils.load_certificates_from_trust_store(
            self.temp_dir
        )
        context = signature_utils.CertificateVerificationContext(cert_tuples)

        self.assertRaisesRegex(
            exception.SignatureVerificationError,
            "The certificate must be an x509.Certificate object.",
            context.update,
            None
        )

    def test_context_verify(self):
        cert_tuples = signature_utils.load_certificates_from_trust_store(
            self.temp_dir
        )
        context = signature_utils.CertificateVerificationContext(cert_tuples)
        cert = signature_utils.load_certificate(
            os.path.join(self.cert_path, 'signed_cert.pem')
        )
        context.update(cert)
        context.verify()
