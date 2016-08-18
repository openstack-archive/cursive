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

from cryptography.hazmat.backends import default_backend
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

    def tearDown(self):
        super(TestCertificateUtils, self).tearDown()

    def load_certificate(self, cert_name):
        # Load the raw certificate file data.
        path = os.path.join(self.cert_path, cert_name)
        with open(path, 'rb') as cert_file:
            data = cert_file.read()

        # Convert the raw certificate data into a certificate object, first
        # as a PEM-encoded certificate and, if that fails, then as a
        # DER-encoded certificate. If both fail, the certificate cannot be
        # loaded.
        try:
            return x509.load_pem_x509_certificate(data, default_backend())
        except Exception:
            try:
                return x509.load_der_x509_certificate(data, default_backend())
            except Exception:
                raise exception.SignatureVerificationError(
                    "Failed to load certificate: %s" % path
                )

    def load_certificates(self, cert_names):
        certs = list()
        for cert_name in cert_names:
            cert = self.load_certificate(cert_name)
            certs.append(cert)
        return certs

    @mock.patch('oslo_utils.timeutils.utcnow')
    def test_is_within_valid_dates(self, mock_utcnow):
        # Verify a certificate is valid at a time within its valid date range
        cert = self.load_certificate('self_signed_cert.pem')
        mock_utcnow.return_value = datetime.datetime(2017, 1, 1)
        result = certificate_utils.is_within_valid_dates(cert)
        self.assertEqual(True, result)

    @mock.patch('oslo_utils.timeutils.utcnow')
    def test_is_before_valid_dates(self, mock_utcnow):
        # Verify a certificate is invalid at a time before its valid date range
        cert = self.load_certificate('self_signed_cert.pem')
        mock_utcnow.return_value = datetime.datetime(2000, 1, 1)
        result = certificate_utils.is_within_valid_dates(cert)
        self.assertEqual(False, result)

    @mock.patch('oslo_utils.timeutils.utcnow')
    def test_is_after_valid_dates(self, mock_utcnow):
        # Verify a certificate is invalid at a time after its valid date range
        cert = self.load_certificate('self_signed_cert.pem')
        mock_utcnow.return_value = datetime.datetime(2100, 1, 1)
        result = certificate_utils.is_within_valid_dates(cert)
        self.assertEqual(False, result)

    def test_is_issuer(self):
        # Test issuer and subject name matching for a self-signed certificate.
        cert = self.load_certificate('self_signed_cert.pem')
        result = certificate_utils.is_issuer(cert, cert)
        self.assertEqual(True, result)

    def test_is_not_issuer(self):
        # Test issuer and subject name mismatching.
        cert = self.load_certificate('self_signed_cert.pem')
        alt = self.load_certificate('orphaned_cert.pem')
        result = certificate_utils.is_issuer(cert, alt)
        self.assertEqual(False, result)

    def test_is_issuer_with_invalid_certs(self):
        # Test issuer check with invalid certificates
        cert = self.load_certificate('self_signed_cert.pem')
        result = certificate_utils.is_issuer(cert, None)
        self.assertEqual(False, result)
        result = certificate_utils.is_issuer(None, cert)
        self.assertEqual(False, result)

    def test_can_sign_certificates(self):
        # Test that a well-formatted certificate can sign
        cert = self.load_certificate('self_signed_cert.pem')
        result = certificate_utils.can_sign_certificates(cert, 'test-ID')
        self.assertEqual(True, result)

    def test_cannot_sign_certificates_without_basic_constraints(self):
        # Verify a certificate without basic constraints cannot sign
        cert = self.load_certificate(
            'self_signed_cert_missing_ca_constraint.pem'
        )
        result = certificate_utils.can_sign_certificates(cert, 'test-ID')
        self.assertEqual(False, result)

    def test_cannot_sign_certificates_with_invalid_basic_constraints(self):
        # Verify a certificate with invalid basic constraints cannot sign
        cert = self.load_certificate(
            'self_signed_cert_invalid_ca_constraint.pem'
        )
        result = certificate_utils.can_sign_certificates(cert, 'test-ID')
        self.assertEqual(False, result)

    def test_cannot_sign_certificates_without_key_usage(self):
        # Verify a certificate without key usage cannot sign
        cert = self.load_certificate('self_signed_cert_missing_key_usage.pem')
        result = certificate_utils.can_sign_certificates(cert, 'test-ID')
        self.assertEqual(False, result)

    def test_cannot_sign_certificates_with_invalid_key_usage(self):
        # Verify a certificate with invalid key usage cannot sign
        cert = self.load_certificate('self_signed_cert_invalid_key_usage.pem')
        result = certificate_utils.can_sign_certificates(cert, 'test-ID')
        self.assertEqual(False, result)

    def test_verify_signing_certificate(self):
        signing_certificate = self.load_certificate('self_signed_cert.pem')
        signed_certificate = self.load_certificate('signed_cert.pem')

        certificate_utils.verify_certificate_signature(
            signing_certificate,
            signed_certificate
        )

    @mock.patch('cursive.signature_utils.get_certificate')
    @mock.patch('oslo_utils.timeutils.utcnow')
    def test_verify_valid_certificate(self, mock_utcnow, mock_get_cert):
        mock_utcnow.return_value = datetime.datetime(2017, 1, 1)
        certs = self.load_certificates(
            ['self_signed_cert.pem', 'self_signed_cert.der',
             'signed_cert.pem']
        )
        mock_get_cert.side_effect = certs
        cert_uuid = '3'
        trusted_cert_uuids = ['1', '2']
        certificate_utils.verify_certificate(
            None, cert_uuid, trusted_cert_uuids
        )

    @mock.patch('cursive.signature_utils.get_certificate')
    @mock.patch('oslo_utils.timeutils.utcnow')
    def test_verify_invalid_certificate(self, mock_utcnow, mock_get_cert):
        mock_utcnow.return_value = datetime.datetime(2017, 1, 1)
        certs = self.load_certificates(
            ['self_signed_cert.pem', 'self_signed_cert.der',
             'orphaned_cert.pem']
        )
        mock_get_cert.side_effect = certs
        cert_uuid = '3'
        trusted_cert_uuids = ['1', '2']
        self.assertRaisesRegex(
            exception.SignatureVerificationError,
            "Certificate chain building failed. Could not locate the "
            "signing certificate for the base certificate in the set of "
            "trusted certificates.",
            certificate_utils.verify_certificate,
            None,
            cert_uuid,
            trusted_cert_uuids
        )

    @mock.patch('cursive.signature_utils.get_certificate')
    @mock.patch('oslo_utils.timeutils.utcnow')
    def test_verify_valid_certificate_with_no_root(self, mock_utcnow,
                                                   mock_get_cert):
        mock_utcnow.return_value = datetime.datetime(2017, 1, 1)

        # Test verifying a valid certificate against an empty list of trusted
        # certificates.
        certs = self.load_certificates(['signed_cert.pem'])
        mock_get_cert.side_effect = certs
        cert_uuid = '3'
        trusted_cert_uuids = []
        self.assertRaisesRegex(
            exception.SignatureVerificationError,
            "Certificate chain building failed. Could not locate the "
            "signing certificate for the base certificate in the set of "
            "trusted certificates.",
            certificate_utils.verify_certificate,
            None,
            cert_uuid,
            trusted_cert_uuids
        )

    @mock.patch('oslo_utils.timeutils.utcnow')
    def test_context_init(self, mock_utcnow):
        # Test constructing a context object with a valid set of certificates
        mock_utcnow.return_value = datetime.datetime(2017, 1, 1)
        certs = self.load_certificates(
            ['self_signed_cert.pem', 'self_signed_cert.der']
        )
        cert_tuples = [('1', certs[0]), ('2', certs[1])]
        context = certificate_utils.CertificateVerificationContext(
            cert_tuples
        )
        self.assertEqual(2, len(context._signing_certificates))
        for t in cert_tuples:
            path, cert = t
            self.assertIn(cert, [x[1] for x in context._signing_certificates])

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
        non_signing_cert = self.load_certificate(
            'self_signed_cert_missing_key_usage.pem'
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
        certs = self.load_certificates(
            ['self_signed_cert.pem', 'self_signed_cert.der']
        )
        cert_tuples = [('1', certs[0]), ('2', certs[1])]
        context = certificate_utils.CertificateVerificationContext(cert_tuples)
        self.assertEqual(0, len(context._signing_certificates))
        self.assertEqual(2, mock_log.warning.call_count)

    @mock.patch('oslo_utils.timeutils.utcnow')
    def test_context_update_with_valid_certificate(self, mock_utcnow):
        # Test updating the context with a valid certificate
        mock_utcnow.return_value = datetime.datetime(2017, 1, 1)
        certs = self.load_certificates(
            ['self_signed_cert.pem', 'self_signed_cert.der']
        )
        cert_tuples = [('1', certs[0]), ('2', certs[1])]
        context = certificate_utils.CertificateVerificationContext(cert_tuples)
        cert = self.load_certificate('orphaned_cert.pem')
        context.update(cert)
        self.assertEqual(cert, context._signed_certificate)

    @mock.patch('oslo_utils.timeutils.utcnow')
    def test_context_update_with_date_invalid_certificate(self, mock_utcnow):
        # Test updating the context with an out-of-date certificate
        mock_utcnow.return_value = datetime.datetime(2017, 1, 1)
        certs = self.load_certificates(
            ['self_signed_cert.pem', 'self_signed_cert.der']
        )
        cert_tuples = [('1', certs[0]), ('2', certs[1])]
        context = certificate_utils.CertificateVerificationContext(cert_tuples)
        cert = self.load_certificate('orphaned_cert.pem')
        mock_utcnow.return_value = datetime.datetime(2100, 1, 1)
        self.assertRaisesRegex(
            exception.SignatureVerificationError,
            "The certificate is outside its valid date range.",
            context.update,
            cert
        )

    def test_context_update_with_invalid_certificate(self):
        # Test updating the context with an invalid certificate
        certs = self.load_certificates(
            ['self_signed_cert.pem', 'self_signed_cert.der']
        )
        cert_tuples = [('1', certs[0]), ('2', certs[1])]
        context = certificate_utils.CertificateVerificationContext(
            cert_tuples
        )

        self.assertRaisesRegex(
            exception.SignatureVerificationError,
            "The certificate must be an x509.Certificate object.",
            context.update,
            None
        )

    @mock.patch('oslo_utils.timeutils.utcnow')
    def test_context_verify(self, mock_utcnow):
        mock_utcnow.return_value = datetime.datetime(2017, 1, 1)
        certs = self.load_certificates(
            ['self_signed_cert.pem', 'self_signed_cert.der']
        )
        cert_tuples = [('1', certs[0]), ('2', certs[1])]

        # Test verification with a two-link certificate chain.
        context = certificate_utils.CertificateVerificationContext(
            cert_tuples
        )
        cert = self.load_certificate('signed_cert.pem')
        context.update(cert)
        context.verify()

        # Test verification with a single-link certificate chain.
        context = certificate_utils.CertificateVerificationContext(
            cert_tuples
        )
        context.update(certs[0])
        context.verify()

    @mock.patch('oslo_utils.timeutils.utcnow')
    def test_context_verify_disable_checks(self, mock_utcnow):
        mock_utcnow.return_value = datetime.datetime(2017, 1, 1)
        certs = self.load_certificates(
            ['self_signed_cert.pem', 'self_signed_cert.der']
        )
        cert_tuples = [('1', certs[0]), ('2', certs[1])]

        # Test verification with a two-link certificate chain.
        context = certificate_utils.CertificateVerificationContext(
            cert_tuples,
            enforce_valid_dates=False,
            enforce_signing_extensions=False,
            enforce_path_length=False
        )
        cert = self.load_certificate('signed_cert.pem')
        context.update(cert)
        context.verify()

        # Test verification with a single-link certificate chain.
        context = certificate_utils.CertificateVerificationContext(
            cert_tuples,
            enforce_valid_dates=False,
            enforce_signing_extensions=False,
            enforce_path_length=False
        )
        context.update(certs[0])
        context.verify()

    @mock.patch('oslo_utils.timeutils.utcnow')
    def test_context_verify_invalid_chain_length(self, mock_utcnow):
        mock_utcnow.return_value = datetime.datetime(2017, 11, 1)
        certs = self.load_certificates(
            ['grandparent_cert.pem', 'parent_cert.pem', 'child_cert.pem']
        )
        cert_tuples = [
            ('1', certs[0]),
            ('2', certs[1]),
            ('3', certs[2])
        ]
        cert = self.load_certificate('grandchild_cert.pem')

        context = certificate_utils.CertificateVerificationContext(
            cert_tuples
        )
        context.update(cert)
        self.assertRaisesRegex(
            exception.SignatureVerificationError,
            "Certificate validation failed. The signing certificate '1' is "
            "not configured to support certificate chains of sufficient "
            "length.",
            context.verify
        )

        context = certificate_utils.CertificateVerificationContext(
            cert_tuples,
            enforce_path_length=False
        )
        context.update(cert)
        context.verify()
