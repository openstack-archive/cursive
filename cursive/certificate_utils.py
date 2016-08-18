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

"""Support certificate validation."""

import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from oslo_log import log as logging
from oslo_utils import timeutils

from cursive import exception
from cursive.i18n import _LE, _LW

LOG = logging.getLogger(__name__)


def load_certificate(path):
    """Load certificate from the provided file.

    :param path: the location of the certificate file
    :return: x509.Certificate object
    :raises: SignatureVerificationError if the certificate fails to load.
    """
    # Load the raw certificate file data.
    with open(path, 'rb') as file_handle:
        data = file_handle.read()

    # Convert the raw certificate data into a certificate object, first as a
    # PEM-encoded certificate and, if that fails, then as a DER-encoded
    # certificate. If both fail, the certificate cannot be loaded.
    try:
        return x509.load_pem_x509_certificate(data, default_backend())
    except Exception:
        try:
            return x509.load_der_x509_certificate(data, default_backend())
        except Exception:
            raise exception.SignatureVerificationError(
                "Failed to load certificate: %s" % path
            )


def load_certificates_from_trust_store(path):
    """Load multiple certificates from the certificate trust store.

    :param path: the location of the certificate trust store directory
    :return: List of tuples each containing the certificate file path and
             the corresponding x509.Certificate object.
    :raises: SignatrueVerificationError if the path is invalid.
    """
    if not os.path.isdir(path):
        raise exception.SignatureVerificationError(
            "The path to the certificate trust store is required."
        )

    certs = []
    for file_name in os.listdir(path):
        file_path = os.path.join(path, file_name)
        if os.path.isfile(file_path):
            try:
                cert = load_certificate(file_path)
            except exception.SignatureVerificationError:
                LOG.warning(_LW("Failed to load certificate: %s"), file_path)
                continue
            else:
                certs.append((file_path, cert))

    return certs


def is_within_valid_dates(certificate):
    """Determine if the certificate is outside it's valid date range.

    :param certificate: the cryptography certificate object
    :return: False if the certificate valid time range does not include
              now, True otherwise.
    """
    # Get now in UTC, since certificate returns times in UTC
    now = timeutils.utcnow()

    # Confirm the certificate valid time range includes now
    if now < certificate.not_valid_before:
        return False
    elif now > certificate.not_valid_after:
        return False
    return True


def is_issuer(issuing_certificate, issued_certificate):
    """Determine if the certificates' subject and issuer names align.

    :param issuing_certificate: the cryptography certificate object that
           is the potential parent of the issued certificate
    :param issued_certificate: the cryptography certificate object that
           is the potential child of the issuing certificate
    :return: True if the issuing certificate is the parent of the issued
             certificate, False otherwise.
    """
    return issuing_certificate.subject == issued_certificate.issuer


def can_sign_certificates(certificate):
    """Determine if the certificate can sign other certificates.

    :param certificate: the cryptography certificate object
    :return: False if the certificate cannot sign other certificates,
             True otherwise.
    """
    try:
        basic_constraints = certificate.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.BASIC_CONSTRAINTS
        ).value
        if not basic_constraints.ca:
            return False
    except x509.extensions.ExtensionNotFound:
        return False

    try:
        key_usage = certificate.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.KEY_USAGE
        ).value
        if not key_usage.key_cert_sign:
            return False
    except x509.extensions.ExtensionNotFound:
        return False

    return True


def verify_certificate_signature(signing_certificate, certificate):
    """Verify that the certificate was signed correctly.

    :param signing_certificate: the cryptography certificate object used to
            sign the certificate
    :param certificate: the cryptography certificate object that was signed
            by the signing certificate
    """
    signature_hash_algorithm = certificate.signature_hash_algorithm
    signature_bytes = certificate.signature
    signer_public_key = signing_certificate.public_key()

    if isinstance(signer_public_key, rsa.RSAPublicKey):
        verifier = signer_public_key.verifier(
            signature_bytes, padding.PKCS1v15(), signature_hash_algorithm
        )
    elif isinstance(signer_public_key, ec.EllipticCurvePublicKey):
        verifier = signer_public_key.verifier(
            signature_bytes, ec.ECDSA(signature_hash_algorithm)
        )
    else:
        verifier = signer_public_key.verifier(
            signature_bytes, signature_hash_algorithm
        )

    verifier.update(certificate.tbs_certificate_bytes)
    verifier.verify()


def verify_certificate(certificate, trust_store_path=None):
    """Verify that the certificate is rooted in the trust store.

    Load all certificates found in the trust store and store them in a
    verification context. Use the context to verify that the certificate is
    cryptographically linked to a certificate chain rooted in the trust store.

    :param certificate:
           the cryptography certificate object
    :param trust_store_path:
           string containing valid filesystem path to the directory acting
           as the certificate trust store (e.g., /etc/ssl/certs)
    :raises: SignatureVerificationError if the certificate verification fails
            for any reason.
    """
    if trust_store_path is None or trust_store_path == '':
        trusted_certificates = []
    else:
        trusted_certificates = load_certificates_from_trust_store(
            trust_store_path
        )

    context = CertificateVerificationContext(trusted_certificates)

    context.update(certificate)
    context.verify()


class CertificateVerificationContext(object):
    """A collection of signing certificates.

    A collection of signing certificates that may be used to verify the
    signatures of other certificates.
    """

    def __init__(self, certificate_tuples):
        self._signing_certificates = []
        for certificate_tuple in certificate_tuples:
            certificate_path, certificate = certificate_tuple
            if not isinstance(certificate, x509.Certificate):
                LOG.error(_LE(
                    "A signing certificate must be an x509.Certificate object."
                ))
                continue

            if not is_within_valid_dates(certificate):
                LOG.warning(_LW(
                    "The '%s' certificate is outside its valid date range "
                    "and cannot be used as a signing certificate."
                ), certificate_path)
                continue

            if can_sign_certificates(certificate):
                self._signing_certificates.append(certificate)
            else:
                LOG.warning(_LW(
                    "The '%s' certificate is not configured to act as a "
                    "signing certificate."
                ), certificate_path)

        self._signed_certificate = None

    def update(self, certificate):
        """Process the certificate to be verified.

        Raises an exception if the certificate is invalid. Stores it
        otherwise.

        :param certificate: the cryptography certificate to be verified
        :raises: SignatureVerificationError if the certificate is not of the
                 right type or if it is outside its valid date range.
        """
        if not isinstance(certificate, x509.Certificate):
            raise exception.SignatureVerificationError(
                "The certificate must be an x509.Certificate object."
            )

        if not is_within_valid_dates(certificate):
            raise exception.SignatureVerificationError(
                "The certificate is outside its valid date range."
            )

        self._signed_certificate = certificate

    def verify(self):
        """Locate the certificate's signing certificate and verify it.

        Locate the signed certificate's signing certificate in the trust store
        cache, using both subject/issuer name matching and signature
        verification. Check that if the certificate is self-signed it is also
        located in the trust store. Verify that the signing certificate can
        have at least one child certificate.

        :raises: SignatureVerificationError if certificate validation fails
                 for any reason, including mismatched signatures or a failure
                 to find the required signing certificate.
        """
        signed_certificate = self._signed_certificate
        certificate_chain = [signed_certificate]

        while True:
            signing_certificate = None

            # Identify potential signing certificates by issuer matching
            for candidate in self._signing_certificates:
                if is_issuer(candidate, signed_certificate):
                    try:
                        verify_certificate_signature(
                            candidate,
                            signed_certificate
                        )
                    except Exception:
                        # If verification fails, an exception is expected. If
                        # an exception is thrown, keep looking for the signing
                        # certificate.
                        continue
                    else:
                        signing_certificate = candidate
                        break

            # If a valid signing certificate is found, prepare to find the
            # next link in the certificate chain. Otherwise, raise an error.
            if signing_certificate:
                # If the certificate is self signed, the root of the
                # certificate chain has been found. Otherwise, repeat the
                # verification process using the newly found signing
                # certificate.
                if signed_certificate == signing_certificate:
                    break
                else:
                    certificate_chain.insert(0, signing_certificate)
                    signed_certificate = signing_certificate
            else:
                raise exception.SignatureVerificationError(
                    "Certificate chain building failed. Could not locate the "
                    "next signing certificate in the certificate trust store."
                )

        # Verify that each certificate's path length constraint allows
        # for it to support the rest of the certificate chain.
        for i in range(len(certificate_chain)):
            certificate = certificate_chain[i]

            # No need to check the last certificate in the chain.
            if certificate == certificate_chain[-1]:
                break

            basic_constraints = certificate.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.BASIC_CONSTRAINTS
            ).value
            if basic_constraints.path_length < len(certificate_chain[i:]):
                raise exception.SignatureVerificationError(
                    "Certificate validation failed. The signing certificate "
                    "is not configured to support certificate chains of "
                    "sufficient length."
                )
