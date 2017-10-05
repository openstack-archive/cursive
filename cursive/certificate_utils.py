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

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509, exceptions as cryptography_exceptions
from oslo_log import log as logging
from oslo_utils import timeutils

from cursive import exception
from cursive import signature_utils

LOG = logging.getLogger(__name__)


def is_within_valid_dates(certificate):
    """Determine if the certificate is outside its valid date range.

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
    """Determine if the issuing cert is the parent of the issued cert.

    Determine if the issuing certificate is the parent of the issued
    certificate by:
    * conducting subject and issuer name matching, and
    * verifying the signature of the issued certificate with the issuing
      certificate's public key

    :param issuing_certificate: the cryptography certificate object that
           is the potential parent of the issued certificate
    :param issued_certificate: the cryptography certificate object that
           is the potential child of the issuing certificate
    :return: True if the issuing certificate is the parent of the issued
             certificate, False otherwise.
    """
    if (issuing_certificate is None) or (issued_certificate is None):
        return False
    elif issuing_certificate.subject != issued_certificate.issuer:
        return False
    else:
        try:
            verify_certificate_signature(
                issuing_certificate,
                issued_certificate
            )
        except cryptography_exceptions.InvalidSignature:
            # If verification fails, an exception is expected.
            return False
        return True


def can_sign_certificates(certificate, certificate_uuid=''):
    """Determine if the certificate can sign other certificates.

    :param certificate: the cryptography certificate object
    :param certificate_uuid: the uuid of the certificate
    :return: False if the certificate cannot sign other certificates,
             True otherwise.
    """
    try:
        basic_constraints = certificate.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.BASIC_CONSTRAINTS
        ).value
    except x509.extensions.ExtensionNotFound:
        LOG.debug(
            "Certificate '%s' does not have a basic constraints extension.",
            certificate_uuid)
        return False

    try:
        key_usage = certificate.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.KEY_USAGE
        ).value
    except x509.extensions.ExtensionNotFound:
        LOG.debug(
            "Certificate '%s' does not have a key usage extension.",
            certificate_uuid)
        return False

    if basic_constraints.ca and key_usage.key_cert_sign:
        return True

    if not basic_constraints.ca:
        LOG.debug(
            "Certificate '%s' is not marked as a CA in its basic constraints "
            "extension.",
            certificate_uuid)
    if not key_usage.key_cert_sign:
        LOG.debug(
            "Certificate '%s' is not marked for verifying certificate "
            "signatures in its key usage extension.",
            certificate_uuid)

    return False


def verify_certificate_signature(signing_certificate, certificate):
    """Verify that the certificate was signed correctly.

    :param signing_certificate: the cryptography certificate object used to
           sign the certificate
    :param certificate: the cryptography certificate object that was signed
           by the signing certificate
    :raises: cryptography.exceptions.InvalidSignature if certificate signature
             verification fails.
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


def verify_certificate(context, certificate_uuid,
                       trusted_certificate_uuids,
                       enforce_valid_dates=True,
                       enforce_signing_extensions=True,
                       enforce_path_length=True):
    """Validate a certificate against a set of trusted certificates.

    From the key manager, load the set of trusted certificates and the
    certificate to validate. Store the trusted certificates in a certificate
    verification context. Use the context to verify that the certificate is
    cryptographically linked to at least one of the trusted certificates.

    :param context: the user context for authentication
    :param certificate_uuid: the uuid of a certificate to validate, stored in
           the key manager
    :param trusted_certificate_uuids: a list containing the uuids of trusted
           certificates stored in the key manager
    :param enforce_valid_dates: a boolean indicating whether date checking
           should be enforced during certificate verification, defaults to
           True
    :param enforce_signing_extensions: a boolean indicating whether extension
           checking should be enforced during certificate verification,
           defaults to True
    :param enforce_path_length: a boolean indicating whether path length
           constraints should be enforced during certificate verification,
           defaults to True
    :raises: SignatureVerificationError if the certificate verification fails
             for any reason.
    """
    trusted_certificates = list()
    for uuid in trusted_certificate_uuids:
        try:
            trusted_certificates.append(
                (uuid, signature_utils.get_certificate(context, uuid))
            )
        except exception.SignatureVerificationError:
            LOG.warning("Skipping trusted certificate: %(id)s" % {'id': uuid})

    certificate = signature_utils.get_certificate(context, certificate_uuid)
    certificate_context = CertificateVerificationContext(
        trusted_certificates,
        enforce_valid_dates=enforce_valid_dates,
        enforce_signing_extensions=enforce_signing_extensions,
        enforce_path_length=enforce_path_length
    )
    certificate_context.update(certificate)
    certificate_context.verify()


class CertificateVerificationContext(object):
    """A collection of signing certificates.

    A collection of signing certificates that may be used to verify the
    signatures of other certificates.
    """

    def __init__(self, certificate_tuples, enforce_valid_dates=True,
                 enforce_signing_extensions=True,
                 enforce_path_length=True):
        self._signing_certificates = []
        for certificate_tuple in certificate_tuples:
            certificate_uuid, certificate = certificate_tuple
            if not isinstance(certificate, x509.Certificate):
                LOG.error(
                    "A signing certificate must be an x509.Certificate object."
                )
                continue

            if enforce_valid_dates:
                if not is_within_valid_dates(certificate):
                    LOG.warning(
                        "Certificate '%s' is outside its valid date range and "
                        "cannot be used as a signing certificate.",
                        certificate_uuid)
                    continue

            if enforce_signing_extensions:
                if not can_sign_certificates(certificate, certificate_uuid):
                    LOG.warning(
                        "Certificate '%s' is not configured to act as a "
                        "signing certificate. It will not be used as a "
                        "signing certificate.",
                        certificate_uuid)
                    continue
            self._signing_certificates.append(certificate_tuple)

        self._signed_certificate = None
        self._enforce_valid_dates = enforce_valid_dates
        self._enforce_path_length = enforce_path_length

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

        if self._enforce_valid_dates:
            if not is_within_valid_dates(certificate):
                raise exception.SignatureVerificationError(
                    "The certificate is outside its valid date range."
                )

        self._signed_certificate = certificate

    def verify(self):
        """Locate the certificate's signing certificate and verify it.

        Locate the certificate's signing certificate in the context
        certificate cache, using both subject/issuer name matching and
        signature verification. If the certificate is self-signed, verify that
        it is also located in the context's certificate cache. Construct the
        certificate chain from certificates in the context certificate cache.
        Verify that the signing certificate can have a sufficient number of
        child certificates to support the chain.

        :raises: SignatureVerificationError if certificate validation fails
                 for any reason, including mismatched signatures or a failure
                 to find the required signing certificate.
        """
        signed_certificate = self._signed_certificate
        certificate_chain = [('base', signed_certificate)]

        # Build the certificate chain.
        while True:
            signing_certificate_tuple = None

            # Search for the signing certificate
            for certificate_tuple in self._signing_certificates:
                _, candidate = certificate_tuple
                if is_issuer(candidate, signed_certificate):
                    signing_certificate_tuple = certificate_tuple
                    break

            # If a valid signing certificate is found, prepare to find the
            # next link in the certificate chain. Otherwise, raise an error.
            if signing_certificate_tuple:
                # If the certificate is self-signed, the root of the
                # certificate chain has been found. Otherwise, repeat the
                # verification process using the newly found signing
                # certificate.
                if signed_certificate == signing_certificate_tuple[1]:
                    break
                else:
                    certificate_chain.insert(0, signing_certificate_tuple)
                    signed_certificate = signing_certificate_tuple[1]
            else:
                uuid = certificate_chain[0][0]
                raise exception.SignatureVerificationError(
                    "Certificate chain building failed. Could not locate the "
                    "signing certificate for %s in the set of trusted "
                    "certificates." %
                    "the base certificate" if uuid == 'base'
                    else "certificate '%s'" % uuid
                )

        if self._enforce_path_length:
            # Verify that each certificate's path length constraint allows
            # for it to support the rest of the certificate chain.
            for i in range(len(certificate_chain)):
                certificate = certificate_chain[i][1]

                # No need to check the last certificate in the chain.
                if certificate == certificate_chain[-1][1]:
                    break

                try:
                    constraints = certificate.extensions.get_extension_for_oid(
                        x509.oid.ExtensionOID.BASIC_CONSTRAINTS
                    ).value
                except x509.extensions.ExtensionNotFound:
                    raise exception.SignatureVerificationError(
                        "Certificate validation failed. The signing "
                        "certificate '%s' does not have a basic constraints "
                        "extension." % certificate_chain[i][0]
                    )

                # Path length only applies to non-self-issued intermediate
                # certificates. Do not include the current or end certificates
                # when computing path length.
                chain_length = len(certificate_chain[i:])
                chain_length = (chain_length - 2) if chain_length > 2 else 0
                if constraints.path_length < chain_length:
                    raise exception.SignatureVerificationError(
                        "Certificate validation failed. The signing "
                        "certificate '%s' is not configured to support "
                        "certificate chains of sufficient "
                        "length." % certificate_chain[i][0]
                    )
