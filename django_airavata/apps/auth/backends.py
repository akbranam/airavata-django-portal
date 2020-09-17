"""Django Airavata Auth Backends: KeycloakBackend."""
import logging
import time

import requests
from django.conf import settings
from django.contrib.auth.models import User
from django.views.decorators.debug import sensitive_variables
from oauthlib.oauth2 import InvalidGrantError, LegacyApplicationClient
from requests_oauthlib import OAuth2Session

from . import models, utils

logger = logging.getLogger(__name__)


class KeycloakBackend(object):
    """Django authentication backend for Keycloak."""

    # mask all local variables from error emails since they contain the user's
    # password and/or client_secret. Note, we could selectively just hide
    # variables that are sensitive, but this decorator doesn't apply explicitly
    # listed variable masking to library function calls
    @sensitive_variables()
    def authenticate(self,
                     request=None,
                     username=None,
                     password=None,
                     refresh_token=None):
        try:
            if username and password:
                token, userinfo = self._get_token_and_userinfo_password_flow(
                    username, password)
                if token is None:  # login failed
                    return None
                self._process_token(request, token)
                return self._process_userinfo(request, userinfo)
            # user is already logged in and can use refresh token
            elif request.user and not utils.is_refresh_token_expired(request):
                logger.debug("Refreshing token...")
                token, userinfo = \
                    self._get_token_and_userinfo_from_refresh_token(request)
                self._process_token(request, token)
                # user is already logged in
                return request.user
            elif refresh_token:
                logger.debug("Refreshing supplied token...")
                token, userinfo = \
                    self._get_token_and_userinfo_from_refresh_token(
                        request, refresh_token=refresh_token)
                self._process_token(request, token)
                return self._process_userinfo(request, userinfo)
            else:
                token, userinfo = self._get_token_and_userinfo_redirect_flow(
                    request)
                self._process_token(request, token)
                return self._process_userinfo(request, userinfo)
        except Exception as e:
            logger.exception("login failed")
            return None

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None

    def _get_token_and_userinfo_password_flow(self, username, password):
        try:
            client_id = settings.KEYCLOAK_CLIENT_ID
            client_secret = settings.KEYCLOAK_CLIENT_SECRET
            token_url = settings.KEYCLOAK_TOKEN_URL
            userinfo_url = settings.KEYCLOAK_USERINFO_URL
            verify_ssl = settings.KEYCLOAK_VERIFY_SSL
            oauth2_session = OAuth2Session(client=LegacyApplicationClient(
                client_id=client_id))
            if hasattr(settings, 'KEYCLOAK_CA_CERTFILE'):
                oauth2_session.verify = settings.KEYCLOAK_CA_CERTFILE
            token = oauth2_session.fetch_token(token_url=token_url,
                                               username=username,
                                               password=password,
                                               client_id=client_id,
                                               client_secret=client_secret,
                                               verify=verify_ssl)
            userinfo = oauth2_session.get(userinfo_url).json()
            return token, userinfo
        except InvalidGrantError as e:
            # password wasn't valid, just log as a warning
            logger.warning(f"Failed to log in user {username} with "
                           f"password: {e}")
            return None, None

    def _get_token_and_userinfo_redirect_flow(self, request):
        authorization_code_url = request.build_absolute_uri()
        client_id = settings.KEYCLOAK_CLIENT_ID
        client_secret = settings.KEYCLOAK_CLIENT_SECRET
        token_url = settings.KEYCLOAK_TOKEN_URL
        userinfo_url = settings.KEYCLOAK_USERINFO_URL
        verify_ssl = settings.KEYCLOAK_VERIFY_SSL
        state = request.session['OAUTH2_STATE']
        redirect_uri = request.session['OAUTH2_REDIRECT_URI']
        logger.debug("state={}".format(state))
        oauth2_session = OAuth2Session(client_id,
                                       scope='openid',
                                       redirect_uri=redirect_uri,
                                       state=state)
        if hasattr(settings, 'KEYCLOAK_CA_CERTFILE'):
            oauth2_session.verify = settings.KEYCLOAK_CA_CERTFILE
        token = oauth2_session.fetch_token(
            token_url, client_secret=client_secret,
            authorization_response=authorization_code_url, verify=verify_ssl)
        userinfo = oauth2_session.get(userinfo_url).json()
        return token, userinfo

    def _get_token_and_userinfo_from_refresh_token(self,
                                                   request,
                                                   refresh_token=None):
        client_id = settings.KEYCLOAK_CLIENT_ID
        client_secret = settings.KEYCLOAK_CLIENT_SECRET
        token_url = settings.KEYCLOAK_TOKEN_URL
        userinfo_url = settings.KEYCLOAK_USERINFO_URL
        verify_ssl = settings.KEYCLOAK_VERIFY_SSL
        oauth2_session = OAuth2Session(client_id, scope='openid')
        if hasattr(settings, 'KEYCLOAK_CA_CERTFILE'):
            oauth2_session.verify = settings.KEYCLOAK_CA_CERTFILE
        refresh_token_ = (refresh_token
                          if refresh_token is not None
                          else request.session['REFRESH_TOKEN'])
        # refresh_token doesn't take client_secret kwarg, so create auth
        # explicitly
        auth = requests.auth.HTTPBasicAuth(client_id, client_secret)
        token = oauth2_session.refresh_token(token_url=token_url,
                                             refresh_token=refresh_token_,
                                             auth=auth,
                                             verify=verify_ssl)
        userinfo = oauth2_session.get(userinfo_url).json()
        return token, userinfo

    def _process_token(self, request, token):
        # TODO validate the JWS signature
        logger.debug("token: {}".format(token))
        now = time.time()
        # Put access_token into session to be used for authenticating with API
        # server
        sess = request.session
        sess['ACCESS_TOKEN'] = token['access_token']
        sess['ACCESS_TOKEN_EXPIRES_AT'] = now + token['expires_in']
        sess['REFRESH_TOKEN'] = token['refresh_token']
        sess['REFRESH_TOKEN_EXPIRES_AT'] = now + token['refresh_expires_in']

    def _process_userinfo(self, request, userinfo):
        logger.debug("userinfo: {}".format(userinfo))
        sub = userinfo['sub']
        username = userinfo['preferred_username']
        email = userinfo['email']
        first_name = userinfo['given_name']
        last_name = userinfo['family_name']

        user = self._get_or_create_user(sub, username)
        user_profile = user.user_profile

        # Save the user info claims
        for (claim, value) in userinfo.items():
            if user_profile.userinfo_set.filter(claim=claim).exists():
                userinfo_claim = user_profile.userinfo_set.get(claim=claim)
                userinfo_claim.value = value
                userinfo_claim.save()
            else:
                user_profile.userinfo_set.create(claim=claim, value=value)

        # Update User model fields
        user = user_profile.user
        user.email = email
        user.first_name = first_name
        user.last_name = last_name
        user.save()
        return user

    def _get_or_create_user(self, sub, username):

        try:
            user_profile = models.UserProfile.objects.get(
                userinfo__claim='sub', userinfo__value=sub)
            return user_profile.user
        except models.UserProfile.DoesNotExist:
            try:
                # For backwards compatibility, lookup by username
                user = User.objects.get(username=username)
                # Make sure there is a user_profile with the sub claim, which
                # will be used to do the lookup next time
                if not hasattr(user, 'user_profile'):
                    user_profile = models.UserProfile(user=user)
                    user_profile.save()
                    user_profile.userinfo_set.create(
                        claim='sub', value=sub)
                else:
                    userinfo = user.user_profile.userinfo_set.get(claim='sub')
                    logger.warning(
                        f"User {username} exists but sub claims don't match: "
                        f"old={userinfo.value}, new={sub}. Updating to new "
                        "sub claim.")
                    userinfo.value = sub
                    userinfo.save()
                return user
            except User.DoesNotExist:
                user = User(username=username)
                user.save()
                user_profile = models.UserProfile(user=user)
                user_profile.save()
                user_profile.userinfo_set.create(claim='sub', value=sub)
                return user
