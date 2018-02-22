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

"""Wrap cryptography verify with verifier."""

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import hashes


class RSAVerifier(object):
    def __init__(self, signature, hash_method, public_key, padding):
        self._signature = signature
        self._hash_method = hash_method
        self._public_key = public_key
        self._padding = padding
        self._hasher = hashes.Hash(hash_method, default_backend())

    def update(self, data):
        self._hasher.update(data)

    def verify(self):
        digest = self._hasher.finalize()
        self._public_key.verify(
            self._signature,
            digest,
            self._padding,
            utils.Prehashed(self._hash_method)
        )


class ECCVerifier(object):
    def __init__(self, signature, hash_method, public_key):
        self._signature = signature
        self._hash_method = hash_method
        self._public_key = public_key
        self._hasher = hashes.Hash(hash_method, default_backend())

    def update(self, data):
        self._hasher.update(data)

    def verify(self):
        digest = self._hasher.finalize()
        self._public_key.verify(
            self._signature,
            digest,
            ec.ECDSA(utils.Prehashed(self._hash_method))
        )


class DSAVerifier(object):
    def __init__(self, signature, hash_method, public_key):
        self._signature = signature
        self._hash_method = hash_method
        self._public_key = public_key
        self._hasher = hashes.Hash(hash_method, default_backend())

    def update(self, data):
        self._hasher.update(data)

    def verify(self):
        digest = self._hasher.finalize()
        self._public_key.verify(
            self._signature,
            digest,
            utils.Prehashed(self._hash_method)
        )
