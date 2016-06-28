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

"""Cursive base exception handling"""

from cursive.i18n import _


class CursiveException(Exception):
    """Base Cursive Exception

    To correctly use this class, inherit from it and define
    a 'msg_fmt' property. That msg_fmt will get printf'd
    with the keyword arguments provided to the constructor.

    """
    msg_fmt = _("An unknown exception occurred.")
    headers = {}
    safe = False

    def __init__(self, message=None, **kwargs):
        self.kwargs = kwargs

        if not message:
            try:
                message = self.msg_fmt % kwargs

            except Exception:
                # at least get the core message out if something happened
                message = self.msg_fmt

        self.message = message
        super(CursiveException, self).__init__(message)

    def format_message(self):
        # NOTE(dane-fichter): use the first argument to the python Exception
        # object which should be our full CursiveException message
        return self.args[0]


class SignatureVerificationError(CursiveException):
    msg_fmt = _("Signature verification for the image "
                "failed: %(reason)s.")
