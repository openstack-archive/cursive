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

import datetime
import mock
import os
import shutil
import tempfile

from cryptography import x509

from cursive import certificate_utils
from cursive import exception
from cursive.tests import base


class TestCertificateUtils(base.TestCase):
    """Test methods for the certificate verification context and utilities"""

    def setUp(self):
        super(TestCertificateUtils, self).setUp()

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
        super(TestCertificateUtils, self).tearDown()

    def test_load_PEM_certificate(self):
        # Test loading a PEM-encoded certificate
        cert = certificate_utils.load_certificate(
            os.path.join(self.temp_dir, 'self_signed_cert.pem')
        )
        self.assertIsInstance(cert, x509.Certificate)

    def test_load_DER_certificate(self):
        # Test loading a DER-encoded certificate
        cert = certificate_utils.load_certificate(
            os.path.join(self.temp_dir, 'self_signed_cert.der')
        )
        self.assertIsInstance(cert, x509.Certificate)

    def test_load_invalid_certificate(self):
        # Test loading a non-certificate file
        path = os.path.join(self.cert_path, 'not_a_cert.txt')
        self.assertRaisesRegex(
            exception.SignatureVerificationError,
            "Failed to load certificate: %s" % path,
            certificate_utils.load_certificate,
            path
        )

    def test_load_valid_certificates_from_valid_trust_store(self):
        # Test loading certificates from a valid certificate directory
        cert_tuples = certificate_utils.load_certificates_from_trust_store(
            self.temp_dir
        )
        self.assertIsInstance(cert_tuples, list)
        self.assertEqual(2, len(cert_tuples))
        for t in cert_tuples:
            self.assertEqual(2, len(t))
            path, cert = t
            self.assertEqual(True, os.path.isfile(path))
            self.assertIsInstance(cert, x509.Certificate)

    @mock.patch('cursive.certificate_utils.LOG')
    def test_load_invalid_certificate_from_valid_trust_store(self, mock_log):
        # Test loading an invalid certificate from a valid directory
        temp_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, temp_dir)
        shutil.copyfile(
            os.path.join(self.cert_path, 'not_a_cert.txt'),
            os.path.join(temp_dir, 'not_a_cert.txt')
        )
        cert_tuples = certificate_utils.load_certificates_from_trust_store(
            temp_dir
        )
        self.assertEqual(1, mock_log.warning.call_count)
        self.assertIsInstance(cert_tuples, list)
        self.assertEqual(0, len(cert_tuples))

    def test_load_certificates_from_empty_trust_store(self):
        # Test loading certificates from an empty valid directory
        temp_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, temp_dir)
        cert_tuples = certificate_utils.load_certificates_from_trust_store(
            temp_dir
        )
        self.assertEqual(0, len(cert_tuples))

    def test_load_certificates_from_invalid_trust_store(self):
        # Test loading certificates from an invalid directory
        self.assertRaisesRegex(
            exception.SignatureVerificationError,
            "The path to the certificate trust store is required.",
            certificate_utils.load_certificates_from_trust_store,
            'invalid-path'
        )

    @mock.patch('oslo_utils.timeutils.utcnow')
    def test_is_within_valid_dates(self, mock_utcnow):
        # Verify a certificate is valid at a time within its valid date range
        cert = certificate_utils.load_certificate(
            os.path.join(self.temp_dir, 'self_signed_cert.pem')
        )
        mock_utcnow.return_value = datetime.datetime(2017, 1, 1)
        result = certificate_utils.is_within_valid_dates(cert)
        self.assertEqual(True, result)

    @mock.patch('oslo_utils.timeutils.utcnow')
    def test_is_before_valid_dates(self, mock_utcnow):
        # Verify a certificate is invalid at a time before its valid date range
        cert = certificate_utils.load_certificate(
            os.path.join(self.temp_dir, 'self_signed_cert.pem')
        )
        mock_utcnow.return_value = datetime.datetime(2000, 1, 1)
        result = certificate_utils.is_within_valid_dates(cert)
        self.assertEqual(False, result)

    @mock.patch('oslo_utils.timeutils.utcnow')
    def test_is_after_valid_dates(self, mock_utcnow):
        # Verify a certificate is invalid at a time after its valid date range
        cert = certificate_utils.load_certificate(
            os.path.join(self.temp_dir, 'self_signed_cert.pem')
        )
        mock_utcnow.return_value = datetime.datetime(2100, 1, 1)
        result = certificate_utils.is_within_valid_dates(cert)
        self.assertEqual(False, result)

    def test_is_issuer(self):
        # Test issuer and subject name matching for a self-signed certificate.
        cert = certificate_utils.load_certificate(
            os.path.join(self.temp_dir, 'self_signed_cert.pem')
        )
        result = certificate_utils.is_issuer(cert, cert)
        self.assertEqual(True, result)

    def test_is_not_issuer(self):
        # Test issuer and subject name mismatching.
        cert = certificate_utils.load_certificate(
            os.path.join(self.temp_dir, 'self_signed_cert.pem')
        )
        alt = certificate_utils.load_certificate(
            os.path.join(self.cert_path, 'orphaned_cert.pem')
        )
        result = certificate_utils.is_issuer(cert, alt)
        self.assertEqual(False, result)

    def test_can_sign_certificates(self):
        # Test that a well-formatted certificate can sign
        cert = certificate_utils.load_certificate(
            os.path.join(self.temp_dir, 'self_signed_cert.pem')
        )
        result = certificate_utils.can_sign_certificates(cert)
        self.assertEqual(True, result)

    def test_cannot_sign_certificates_without_basic_constraints(self):
        # Verify a certificate without basic constraints cannot sign
        cert = certificate_utils.load_certificate(
            os.path.join(
                self.cert_path,
                'self_signed_cert_missing_ca_constraint.pem'
            )
        )
        result = certificate_utils.can_sign_certificates(cert)
        self.assertEqual(False, result)

    def test_cannot_sign_certificates_with_invalid_basic_constraints(self):
        # Verify a certificate with invalid basic constraints cannot sign
        cert = certificate_utils.load_certificate(
            os.path.join(
                self.cert_path,
                'self_signed_cert_invalid_ca_constraint.pem'
            )
        )
        result = certificate_utils.can_sign_certificates(cert)
        self.assertEqual(False, result)

    def test_cannot_sign_certificates_without_key_usage(self):
        # Verify a certificate without key usage cannot sign
        cert = certificate_utils.load_certificate(
            os.path.join(
                self.cert_path,
                'self_signed_cert_missing_key_usage.pem'
            )
        )
        result = certificate_utils.can_sign_certificates(cert)
        self.assertEqual(False, result)

    def test_cannot_sign_certificates_with_invalid_key_usage(self):
        # Verify a certificate with invalid key usage cannot sign
        cert = certificate_utils.load_certificate(
            os.path.join(
                self.cert_path,
                'self_signed_cert_invalid_key_usage.pem'
            )
        )
        result = certificate_utils.can_sign_certificates(cert)
        self.assertEqual(False, result)

    def test_verify_signing_certificate(self):
        signing_certificate = certificate_utils.load_certificate(
            os.path.join(self.cert_path, 'self_signed_cert.pem')
        )
        signed_certificate = certificate_utils.load_certificate(
            os.path.join(self.cert_path, 'signed_cert.pem')
        )

        certificate_utils.verify_certificate_signature(
            signing_certificate,
            signed_certificate
        )

    def test_verify_valid_certificate(self):
        # Test verifying a valid certificate
        cert = certificate_utils.load_certificate(
            os.path.join(self.cert_path, 'signed_cert.pem')
        )
        certificate_utils.verify_certificate(cert, self.temp_dir)

    def test_verify_invalid_certificate(self):
        # Test verifying an invalid certificate
        cert = certificate_utils.load_certificate(
            os.path.join(self.cert_path, 'orphaned_cert.pem')
        )
        self.assertRaisesRegex(
            exception.SignatureVerificationError,
            "Certificate chain building failed. Could not locate the "
            "next signing certificate in the certificate trust store.",
            certificate_utils.verify_certificate,
            cert,
            self.temp_dir
        )

    def test_verify_valid_certificate_with_empty_trust_store(self):
        # Test verifying a valid certificate against an empty trust store
        cert = certificate_utils.load_certificate(
            os.path.join(self.cert_path, 'signed_cert.pem')
        )
        self.assertRaisesRegex(
            exception.SignatureVerificationError,
            "Certificate chain building failed. Could not locate the "
            "next signing certificate in the certificate trust store.",
            certificate_utils.verify_certificate,
            cert,
            ''
        )

        self.assertRaisesRegex(
            exception.SignatureVerificationError,
            "Certificate chain building failed. Could not locate the "
            "next signing certificate in the certificate trust store.",
            certificate_utils.verify_certificate,
            cert,
            None
        )

    @mock.patch('oslo_utils.timeutils.utcnow')
    def test_context_init(self, mock_utcnow):
        # Test constructing a context object with a valid set of certificates
        mock_utcnow.return_value = datetime.datetime(2017, 1, 1)
        cert_tuples = certificate_utils.load_certificates_from_trust_store(
            self.temp_dir
        )
        context = certificate_utils.CertificateVerificationContext(
            cert_tuples
        )
        self.assertEqual(2, len(context._signing_certificates))
        for t in cert_tuples:
            path, cert = t
            self.assertIn(cert, context._signing_certificates)

    @mock.patch('cursive.certificate_utils.LOG')
    @mock.patch('oslo_utils.timeutils.utcnow')
    def test_context_init_with_invalid_certificate(self, mock_utcnow,
                                                   mock_log):
        # Test constructing a context object with an invalid certificate
        mock_utcnow.return_value = datetime.datetime(2017, 1, 1)
        alt_cert_tuples = [('path', None)]
        context = certificate_utils.CertificateVerificationContext(
            alt_cert_tuples
        )
        self.assertEqual(0, len(context._signing_certificates))
        self.assertEqual(1, mock_log.error.call_count)

    @mock.patch('cursive.certificate_utils.LOG')
    @mock.patch('oslo_utils.timeutils.utcnow')
    def test_context_init_with_non_signing_certificate(self, mock_utcnow,
                                                       mock_log):
        # Test constructing a context object with an non-signing certificate
        mock_utcnow.return_value = datetime.datetime(2017, 1, 1)
        non_signing_cert = certificate_utils.load_certificate(
            os.path.join(
                self.cert_path,
                'self_signed_cert_missing_key_usage.pem'
            )
        )
        alt_cert_tuples = [('path', non_signing_cert)]
        context = certificate_utils.CertificateVerificationContext(
            alt_cert_tuples
        )
        self.assertEqual(0, len(context._signing_certificates))
        self.assertEqual(1, mock_log.warning.call_count)

    @mock.patch('cursive.certificate_utils.LOG')
    @mock.patch('oslo_utils.timeutils.utcnow')
    def test_context_init_with_out_of_date_certificate(self, mock_utcnow,
                                                       mock_log):
        # Test constructing a context object with out-of-date certificates
        mock_utcnow.return_value = datetime.datetime(2100, 1, 1)
        cert_tuples = certificate_utils.load_certificates_from_trust_store(
            self.temp_dir
        )
        context = certificate_utils.CertificateVerificationContext(cert_tuples)
        self.assertEqual(0, len(context._signing_certificates))
        self.assertEqual(2, mock_log.warning.call_count)

    @mock.patch('oslo_utils.timeutils.utcnow')
    def test_context_update_with_valid_certificate(self, mock_utcnow):
        # Test updating the context with a valid certificate
        mock_utcnow.return_value = datetime.datetime(2017, 1, 1)
        cert_tuples = certificate_utils.load_certificates_from_trust_store(
            self.temp_dir
        )
        context = certificate_utils.CertificateVerificationContext(cert_tuples)
        cert = certificate_utils.load_certificate(
            os.path.join(self.cert_path, 'orphaned_cert.pem')
        )
        context.update(cert)
        self.assertEqual(cert, context._signed_certificate)

    @mock.patch('oslo_utils.timeutils.utcnow')
    def test_context_update_with_date_invalid_certificate(self, mock_utcnow):
        # Test updating the context with an out-of-date certificate
        mock_utcnow.return_value = datetime.datetime(2017, 1, 1)
        cert_tuples = certificate_utils.load_certificates_from_trust_store(
            self.temp_dir
        )
        context = certificate_utils.CertificateVerificationContext(cert_tuples)
        cert = certificate_utils.load_certificate(
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
        cert_tuples = certificate_utils.load_certificates_from_trust_store(
            self.temp_dir
        )
        context = certificate_utils.CertificateVerificationContext(
            cert_tuples
        )

        self.assertRaisesRegex(
            exception.SignatureVerificationError,
            "The certificate must be an x509.Certificate object.",
            context.update,
            None
        )

    def test_context_verify(self):
        cert_tuples = certificate_utils.load_certificates_from_trust_store(
            self.temp_dir
        )
        context = certificate_utils.CertificateVerificationContext(
            cert_tuples
        )
        cert = certificate_utils.load_certificate(
            os.path.join(self.cert_path, 'signed_cert.pem')
        )
        context.update(cert)
        context.verify()
