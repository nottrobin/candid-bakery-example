# -*- coding: utf-8 -*-

import json

from datetime import datetime, timedelta
from urllib.parse import urljoin

from flask import Flask, escape, request
from macaroonbakery import bakery, checkers, httpbakery
from macaroonbakery.httpbakery import agent


def _identity_caveats():
    """Caveats required for user authentication using Candid."""
    return [
        checkers.need_declared_caveat(
            checkers.Caveat(location='https://api.staging.jujucharms.com/identity',
                            condition='is-authenticated-user'),
            ['username']
        )
    ]


class Identity(bakery.Identity):
    """Identity information for a Candid third party caveat."""

    def __init__(self, identity):
        parts = identity.split('@', 1)
        self._username = parts[0]
        self._domain = parts[1] if len(parts) == 2 else ''

    def username(self):
        return self._username

    def domain(self):
        return self._domain


class IdentityClient(bakery.IdentityClient):
    """Basic identity client based on the username returned by Candid."""

    def identity_from_context(self, ctx):
        """Return the identity based on information in the context.

        If it cannot determine the identity based on the context, then it
        should return a set of caveats containing a third party caveat that,
        when discharged, can be used to obtain the identity with
        declared_identity.

        A (bakery) auth context is passed during macaroon verification,
        and it could include HTTP headers or any other additional information.

        """
        # identity is extracted from the macaroons
        return None, _identity_caveats()

    def declared_identity(self, ctx, declared):
        """Return the identity from the given declared attributes."""
        username = declared.get('username')
        if username is None:
            raise bakery.IdentityError('no username found')
        return Identity(username)


class MacaroonBakery:
    """Issue and verify Candid authenticated macaroons."""

    def __init__(self, locator=None):
        locator = httpbakery.ThirdPartyLocator()

        # generate a new keypair for encrypting third party caveats
        # it's safe to use a new keypair every time the server starts
        # as it's used only for encrypting the third party caveats
        # for sending them to be discharged. The private key doesn't need
        # to survive across restarts.
        key = bakery.generate_key()

        location = 'localhost:8000'
        root_key = 'private-key'

        self._bakery = bakery.Bakery(
            location=location, locator=locator,
            identity_client=IdentityClient(), key=key,
            root_key_store=bakery.MemoryKeyStore(root_key))

    def new(self):
        """Return a new macaroon requiring a Candid discharge."""
        caveats = _identity_caveats()
        return self._bakery.oven.macaroon(
            version=bakery.VERSION_2,
            expiry=datetime.utcnow() + timedelta(seconds=600),
            caveats=caveats,
            ops=[bakery.LOGIN_OP])

    def verify(self, macaroons):
        """Verify macaroons and return authenticated user details."""
        auth_checker = self._bakery.checker.auth(macaroons)
        ctx = checkers.AuthContext()

        # raises DischargeRequiredError if invalid auth or expired macaroon
        auth_info = auth_checker.allow(ctx, [bakery.LOGIN_OP])

        user = auth_info.identity
        return {'username': user.username(), 'domain': user.domain()}


# bakery instance handling macaroons creation/verification
bkry = MacaroonBakery()


def _authenticate(request):
    headers = request.headers
    macaroons = httpbakery.extract_macaroons(headers)
    u = bkry.verify(macaroons)
    return u


app = Flask(__name__)


@app.route('/')
def whoami():
    """Return authenticated user details."""
    try:
        account = _authenticate(request)
    except:
        content, headers = httpbakery.discharge_required_response(
            bkry.new(), '/', 'cookie-suffix')
        return content, 401, headers
    return account, 200

