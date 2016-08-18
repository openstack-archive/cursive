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

"""Support signature verification."""

import binascii
import os

from castellan.common.exception import KeyManagerError
from castellan import key_manager
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from oslo_log import log as logging
from oslo_serialization import base64
from oslo_utils import encodeutils
from oslo_utils import timeutils

from cursive import exception
from cursive.i18n import _, _LE, _LW

LOG = logging.getLogger(__name__)


HASH_METHODS = {
    'SHA-224': hashes.SHA224(),
    'SHA-256': hashes.SHA256(),
    'SHA-384': hashes.SHA384(),
    'SHA-512': hashes.SHA512(),
}

# Currently supported signature key types
# RSA Options
RSA_PSS = 'RSA-PSS'
# DSA Options
DSA = 'DSA'

# ECC curves -- note that only those with key sizes >=384 are included
# Note also that some of these may not be supported by the cryptography backend
ECC_CURVES = (
    ec.SECT571K1(),
    ec.SECT409K1(),
    ec.SECT571R1(),
    ec.SECT409R1(),
    ec.SECP521R1(),
    ec.SECP384R1(),
)

# These are the currently supported certificate formats
X_509 = 'X.509'

CERTIFICATE_FORMATS = {
    X_509,
}

# These are the currently supported MGF formats, used for RSA-PSS signatures
MASK_GEN_ALGORITHMS = {
    'MGF1': padding.MGF1,
}


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


# Required image property names
(SIGNATURE, HASH_METHOD, KEY_TYPE, CERT_UUID) = (
    'img_signature',
    'img_signature_hash_method',
    'img_signature_key_type',
    'img_signature_certificate_uuid'
)


class SignatureKeyType(object):

    _REGISTERED_TYPES = {}

    def __init__(self, name, public_key_type, create_verifier):
        self.name = name
        self.public_key_type = public_key_type
        self.create_verifier = create_verifier

    @classmethod
    def register(cls, name, public_key_type, create_verifier):
        """Register a signature key type.

        :param name: the name of the signature key type
        :param public_key_type: e.g. RSAPublicKey, DSAPublicKey, etc.
        :param create_verifier: a function to create a verifier for this type
        """
        cls._REGISTERED_TYPES[name] = cls(name,
                                          public_key_type,
                                          create_verifier)

    @classmethod
    def lookup(cls, name):
        """Look up the signature key type.

        :param name: the name of the signature key type
        :returns: the SignatureKeyType object
        :raises: SignatureVerificationError if signature key type is invalid
        """
        if name not in cls._REGISTERED_TYPES:
            raise exception.SignatureVerificationError(
                reason=_('Invalid signature key type: %s') % name)
        return cls._REGISTERED_TYPES[name]


# each key type will require its own verifier
def create_verifier_for_pss(signature, hash_method, public_key):
    """Create the verifier to use when the key type is RSA-PSS.

    :param signature: the decoded signature to use
    :param hash_method: the hash method to use, as a cryptography object
    :param public_key: the public key to use, as a cryptography object
    :raises: SignatureVerificationError if the RSA-PSS specific properties
                                        are invalid
    :returns: the verifier to use to verify the signature for RSA-PSS
    """
    # default to MGF1
    mgf = padding.MGF1(hash_method)

    # default to max salt length
    salt_length = padding.PSS.MAX_LENGTH

    # return the verifier
    return public_key.verifier(
        signature,
        padding.PSS(mgf=mgf, salt_length=salt_length),
        hash_method
    )


def create_verifier_for_ecc(signature, hash_method, public_key):
    """Create the verifier to use when the key type is ECC_*.

    :param signature: the decoded signature to use
    :param hash_method: the hash method to use, as a cryptography object
    :param public_key: the public key to use, as a cryptography object
    :returns: the verifier to use to verify the signature for ECC_*.
    """
    # return the verifier
    return public_key.verifier(
        signature,
        ec.ECDSA(hash_method)
    )


def create_verifier_for_dsa(signature, hash_method, public_key):
    """Create the verifier to use when the key type is DSA

    :param signature: the decoded signature to use
    :param hash_method: the hash method to use, as a cryptography object
    :param public_key: the public key to use, as a cryptography object
    :returns: the verifier to use to verify the signature for DSA
    """
    # return the verifier
    return public_key.verifier(
        signature,
        hash_method
    )


SignatureKeyType.register(RSA_PSS, rsa.RSAPublicKey, create_verifier_for_pss)
SignatureKeyType.register(DSA, dsa.DSAPublicKey, create_verifier_for_dsa)

# Register the elliptic curves which are supported by the backend
for curve in ECC_CURVES:
    if default_backend().elliptic_curve_supported(curve):
        SignatureKeyType.register('ECC_' + curve.name.upper(),
                                  ec.EllipticCurvePublicKey,
                                  create_verifier_for_ecc)


def should_create_verifier(image_properties):
    """Determine whether a verifier should be created.

    Using the image properties, determine whether existing properties indicate
    that signature verification should be done.

    :param image_properties: the key-value properties about the image
    :return: True, if signature metadata properties exist, False otherwise
    """
    return (image_properties is not None and
            CERT_UUID in image_properties and
            HASH_METHOD in image_properties and
            SIGNATURE in image_properties and
            KEY_TYPE in image_properties)


def get_verifier(context, img_signature_certificate_uuid,
                 img_signature_hash_method, img_signature,
                 img_signature_key_type, trust_store_path=None):
    """Instantiate signature properties and use them to create a verifier.

    :param context: the user context for authentication
    :param img_signature_certificate_uuid:
           uuid of signing certificate stored in key manager
    :param img_signature_hash_method:
           string denoting hash method used to compute signature
    :param img_signature: string of base64 encoding of signature
    :param img_signature_key_type:
           string denoting type of keypair used to compute signature
    :param trust_store_path:
           string containing valid filesystem path to the directory acting
           as the certificate trust store (e.g., /etc/ssl/certs)
    :returns: instance of
       cryptography.hazmat.primitives.asymmetric.AsymmetricVerificationContext
    :raises: SignatureVerificationError if we fail to build the verifier
    """
    image_meta_props = {'img_signature_uuid': img_signature_certificate_uuid,
                        'img_signature_hash_method': img_signature_hash_method,
                        'img_signature': img_signature,
                        'img_signature_key_type': img_signature_key_type}
    for key in image_meta_props.keys():
        if image_meta_props[key] is None:
            raise exception.SignatureVerificationError(
                reason=_('Required image properties for signature verification'
                         ' do not exist. Cannot verify signature. Missing'
                         ' property: %s') % key)

    signature = get_signature(img_signature)
    hash_method = get_hash_method(img_signature_hash_method)
    signature_key_type = SignatureKeyType.lookup(img_signature_key_type)
    public_key = get_public_key(context,
                                img_signature_certificate_uuid,
                                signature_key_type,
                                trust_store_path)

    # create the verifier based on the signature key type
    verifier = signature_key_type.create_verifier(signature,
                                                  hash_method,
                                                  public_key)
    if verifier:
        return verifier
    else:
        # Error creating the verifier
        raise exception.SignatureVerificationError(
            reason=_('Error occurred while creating the verifier'))


def get_signature(signature_data):
    """Decode the signature data and returns the signature.

    :param signature_data: the base64-encoded signature data
    :returns: the decoded signature
    :raises: SignatureVerificationError if the signature data is malformatted
    """
    try:
        signature = base64.decode_as_bytes(signature_data)
    except (TypeError, binascii.Error):
        raise exception.SignatureVerificationError(
            reason=_('The signature data was not properly '
                     'encoded using base64'))

    return signature


def get_hash_method(hash_method_name):
    """Verify the hash method name and create the hash method.

    :param hash_method_name: the name of the hash method to retrieve
    :returns: the hash method, a cryptography object
    :raises: SignatureVerificationError if the hash method name is invalid
    """
    if hash_method_name not in HASH_METHODS:
        raise exception.SignatureVerificationError(
            reason=_('Invalid signature hash method: %s') % hash_method_name)

    return HASH_METHODS[hash_method_name]


def get_public_key(context, signature_certificate_uuid, signature_key_type,
                   trust_store_path=None):
    """Create the public key object from a retrieved certificate.

    :param context: the user context for authentication
    :param signature_certificate_uuid: the uuid to use to retrieve the
                                       certificate
    :param signature_key_type: a SignatureKeyType object
    :param trust_store_path:
           string containing valid filesystem path to the directory acting
           as the certificate trust store (e.g., /etc/ssl/certs)
    :returns: the public key cryptography object
    :raises: SignatureVerificationError if public key format is invalid
    """
    certificate = get_certificate(context, signature_certificate_uuid)
    verify_certificate(certificate, trust_store_path)

    # Note that this public key could either be
    # RSAPublicKey, DSAPublicKey, or EllipticCurvePublicKey
    public_key = certificate.public_key()

    # Confirm the type is of the type expected based on the signature key type
    if not isinstance(public_key, signature_key_type.public_key_type):
        raise exception.SignatureVerificationError(
            reason=_('Invalid public key type for signature key type: %s')
            % signature_key_type.name)

    return public_key


def get_certificate(context, signature_certificate_uuid):
    """Create the certificate object from the retrieved certificate data.

    :param context: the user context for authentication
    :param signature_certificate_uuid: the uuid to use to retrieve the
                                       certificate
    :returns: the certificate cryptography object
    :raises: SignatureVerificationError if the retrieval fails or the format
             is invalid
    """
    keymgr_api = key_manager.API()

    try:
        # The certificate retrieved here is a castellan certificate object
        cert = keymgr_api.get(context, signature_certificate_uuid)
    except KeyManagerError as e:
        # The problem encountered may be backend-specific, since castellan
        # can use different backends.  Rather than importing all possible
        # backends here, the generic "Exception" is used.
        msg = (_LE("Unable to retrieve certificate with ID %(id)s: %(e)s")
               % {'id': signature_certificate_uuid,
                  'e': encodeutils.exception_to_unicode(e)})
        LOG.error(msg)
        raise exception.SignatureVerificationError(
            reason=_('Unable to retrieve certificate with ID: %s')
            % signature_certificate_uuid)

    if cert.format not in CERTIFICATE_FORMATS:
        raise exception.SignatureVerificationError(
            reason=_('Invalid certificate format: %s') % cert.format)

    if cert.format == X_509:
        # castellan always encodes certificates in DER format
        cert_data = cert.get_encoded()
        certificate = x509.load_der_x509_certificate(cert_data,
                                                     default_backend())

    return certificate
