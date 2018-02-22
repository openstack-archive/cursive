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

from castellan.common.exception import KeyManagerError
from castellan.common.exception import ManagedObjectNotFoundError
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

from cursive import exception
from cursive.i18n import _, _LE
from cursive import verifiers

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


# Required image property names
(SIGNATURE, HASH_METHOD, KEY_TYPE, CERT_UUID) = (
    'img_signature',
    'img_signature_hash_method',
    'img_signature_key_type',
    'img_signature_certificate_uuid'
)


class SignatureKeyType(object):

    REGISTERED_TYPES = {}

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
        cls.REGISTERED_TYPES[name] = cls(name,
                                         public_key_type,
                                         create_verifier)

    @classmethod
    def lookup(cls, name):
        """Look up the signature key type.

        :param name: the name of the signature key type
        :returns: the SignatureKeyType object
        :raises: SignatureVerificationError if signature key type is invalid
        """
        if name not in cls.REGISTERED_TYPES:
            raise exception.SignatureVerificationError(
                reason=_('Invalid signature key type: %s') % name)
        return cls.REGISTERED_TYPES[name]


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
    # confirm none of the inputs are None
    if not signature or not hash_method or not public_key:
        return None

    # default to MGF1
    mgf = padding.MGF1(hash_method)

    # default to max salt length
    salt_length = padding.PSS.MAX_LENGTH

    # return the verifier
    return verifiers.RSAVerifier(
        signature,
        hash_method,
        public_key,
        padding.PSS(
            mgf=mgf,
            salt_length=salt_length
        )
    )


def create_verifier_for_ecc(signature, hash_method, public_key):
    """Create the verifier to use when the key type is ECC_*.

    :param signature: the decoded signature to use
    :param hash_method: the hash method to use, as a cryptography object
    :param public_key: the public key to use, as a cryptography object
    :returns: the verifier to use to verify the signature for ECC_*.
    """
    # confirm none of the inputs are None
    if not signature or not hash_method or not public_key:
        return None

    # return the verifier
    return verifiers.ECCVerifier(
        signature,
        hash_method,
        public_key,
    )


def create_verifier_for_dsa(signature, hash_method, public_key):
    """Create the verifier to use when the key type is DSA

    :param signature: the decoded signature to use
    :param hash_method: the hash method to use, as a cryptography object
    :param public_key: the public key to use, as a cryptography object
    :returns: the verifier to use to verify the signature for DSA
    """
    # confirm none of the inputs are None
    if not signature or not hash_method or not public_key:
        return None

    # return the verifier
    return verifiers.DSAVerifier(
        signature,
        hash_method,
        public_key,
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
                 img_signature_key_type):
    """Instantiate signature properties and use them to create a verifier.

    :param context: the user context for authentication
    :param img_signature_certificate_uuid:
           uuid of signing certificate stored in key manager
    :param img_signature_hash_method:
           string denoting hash method used to compute signature
    :param img_signature: string of base64 encoding of signature
    :param img_signature_key_type:
           string denoting type of keypair used to compute signature
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
                                signature_key_type)

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


def get_public_key(context, signature_certificate_uuid, signature_key_type):
    """Create the public key object from a retrieved certificate.

    :param context: the user context for authentication
    :param signature_certificate_uuid: the uuid to use to retrieve the
                                       certificate
    :param signature_key_type: a SignatureKeyType object
    :returns: the public key cryptography object
    :raises: SignatureVerificationError if public key format is invalid
    """
    certificate = get_certificate(context, signature_certificate_uuid)

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
    except ManagedObjectNotFoundError as e:
        raise exception.SignatureVerificationError(
            reason=_('Certificate not found with ID: %s')
            % signature_certificate_uuid)
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
