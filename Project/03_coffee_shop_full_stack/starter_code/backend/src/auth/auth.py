import os
import json
from flask import request, _request_ctx_stack, abort
from functools import wraps
from jose import jwt
from urllib.request import urlopen
from dotenv import load_dotenv

load_dotenv()

AUTH0_DOMAIN = os.getenv('AUTH0_DOMAIN')
ALGORITHMS = os.getenv('ALGORITHMS')
API_AUDIENCE = os.getenv('API_AUDIENCE')


# AuthError Exception
'''
AuthError Exception
A standardized way to communicate auth failure modes
'''


class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


# Auth Header

'''
@TODO implement get_token_auth_header() method
    it should attempt to get the header from the request
        it should raise an AuthError if no header is present
    it should attempt to split bearer and the token
        it should raise an AuthError if the header is malformed
    return the token part of the header
'''


def get_token_auth_header():
    if 'Authorization' not in request.headers:
        raise AuthError({
            'code': 'Invalid claim',
            'description': 'Authorization not present'
        }, 400)

    auth_header = request.headers['Authorization'].split(' ')

    if auth_header[0].upper() != 'BEARER':
        raise AuthError({
            'code': 'Malformed header',
            'description': 'Auth type "Bearer" is missing'
        }, 401)

    elif len(auth_header) == 1:
        raise AuthError({
            'code': 'Missing Token',
            'description': 'Token not found '
        }, 401)

    elif len(auth_header) > 2:
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization header must be bearer token.'
        }, 401)

    token = auth_header[1]

    return token


'''
@TODO implement check_permissions(permission, payload) method
    @INPUTS
        permission: string permission (i.e. 'post:drink')
        payload: decoded jwt payload

    it should raise an AuthError if permissions are not included in the payload
        !!NOTE check your RBAC settings in Auth0
    it should raise an AuthError if the requested permission string is not in the payload permissions array
    return true otherwise
'''


def check_permissions(permission, payload):
    if 'permissions' not in payload:
        raise AuthError({
            'code': 'invalid claim',
            'description': 'Permission not set in header'
        }, 400)

    if permission not in payload['permissions']:
        raise AuthError({
            'code': 'invalid permission',
            'description': f'permission {permission}, not found'
        }, 403)

    return True


'''
@TODO implement verify_decode_jwt(token) method
    @INPUTS
        token: a json web token (string)

    it should be an Auth0 token with key id (kid)
    it should verify the token using Auth0 /.well-known/jwks.json
    it should decode the payload from the token
    it should validate the claims
    return the decoded payload

    !!NOTE urlopen has a common certificate error described here: https://stackoverflow.com/questions/50236117/scraping-ssl-certificate-verify-failed-error-for-http-en-wikipedia-org
'''

# https://asahel.eu.auth0.com/authorize?audience=coffee&response_type=token&client_id=IeCXhLFgfTKtPF1oFRHP4y5iZZGzJrvX&redirect_uri=https://127.0.0.1:8080/login-requests

# Manager
# eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InM5S2FaYWI3cHY5Q00zemZSUFljNCJ9.eyJpc3MiOiJodHRwczovL2FzYWhlbC5ldS5hdXRoMC5jb20vIiwic3ViIjoiYXV0aDB8NjMwNzgyY2ZlNTdiMDA4NjhhMjE4MjRmIiwiYXVkIjoiY29mZmVlIiwiaWF0IjoxNjYxNTE5NTk4LCJleHAiOjE2NjE1MjY3OTgsImF6cCI6IkllQ1hoTEZnZlRLdFBGMW9GUkhQNHk1aVpaR3pKcnZYIiwic2NvcGUiOiIiLCJwZXJtaXNzaW9ucyI6WyJkZWxldGU6ZHJpbmtzIiwiZ2V0OmRyaW5rcyIsImdldDpkcmlua3MtZGV0YWlsIiwicGF0Y2g6ZHJpbmtzIiwicG9zdDpkcmlua3MiXX0.Va33pTr7n0pF3qCYY72B9Ej4s8WwXB6ZHOqRYsEIdVqBXdwScG8XRYPUqSyjvPOS9Eea9bKRzWxLBAkICaPyqTGdNbERWl5Bvn4w7Xeg0QMDimH0fvvcT6PXOIXvnpXU2pVluGD_KtUcZlHRF2Beuu-UaFc0rzlAyQ655fDvnWFBjKn5fXZg_B3_1RokedBm3dBv1euRUFOM0bR-asJbO_jZ8j-uSlPA2KKwxqsR5J-Dw7BBzQaXKC_IIfVVWqz4dPLIokrZJva7Q46AJeI7-DWywZzyH52gRhURkVhFdPZOp3BgDzXampVmpilt8_aezfKeFUvCAfg3ohezLc34fQ

# Barista
# eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InM5S2FaYWI3cHY5Q00zemZSUFljNCJ9.eyJpc3MiOiJodHRwczovL2FzYWhlbC5ldS5hdXRoMC5jb20vIiwic3ViIjoiYXV0aDB8NjMwNzgyN2Q1MTNkZTNmNGNmYTBiMzg5IiwiYXVkIjoiY29mZmVlIiwiaWF0IjoxNjYxNTE5NzUwLCJleHAiOjE2NjE1MjY5NTAsImF6cCI6IkllQ1hoTEZnZlRLdFBGMW9GUkhQNHk1aVpaR3pKcnZYIiwic2NvcGUiOiIiLCJwZXJtaXNzaW9ucyI6WyJnZXQ6ZHJpbmtzIiwiZ2V0OmRyaW5rcy1kZXRhaWwiXX0.eFsDQqWR1osLxpAx--vXVZJ6lAS7XXrR_O1HtTqvCt-iDNtf6pfPSTTPk2g_XMBpB8kISPnndznlZSM8G1eMzqx-wTm7xK76Z6sT7TIv71GWrfNGWs6VgW-QwHtsD2i_UiDUxBiKoBDBydOFiZ9zqKAgbhUELOxlGefY7-lDU4LSqhXmslPBH4LMBSvFiqpzgRQ7zp0wPMfaASXad5BkUlCU3G7P593FwlQ8wqUIaCDcNRS9nHgtx6x_XXlrxyl5DM48klp92eMUvh2CMryKBiFK6sPPOlANeeSl_CcLY4wVTcW6kdftI_AFYK8pgEwtCKUppkla-64KLFXBjKAWEg


def verify_decode_jwt(token):
    jsonurl = urlopen(f'https://{AUTH0_DOMAIN}/.well-known/jwks.json')
    jwks = json.loads(jsonurl.read())
    unverified_header = jwt.get_unverified_header(token)
    rsa_key = {}
    if 'kid' not in unverified_header:
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization malformed.'
        }, 401)

    for key in jwks['keys']:
        if key['kid'] == unverified_header['kid']:
            rsa_key = {
                'kty': key['kty'],
                'kid': key['kid'],
                'use': key['use'],
                'n': key['n'],
                'e': key['e']
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=API_AUDIENCE,
                issuer='https://' + AUTH0_DOMAIN + '/'
            )

            return payload

        except jwt.ExpiredSignatureError:
            raise AuthError({
                'code': 'token_expired',
                'description': 'Token expired.'
            }, 401)

        except jwt.JWTClaimsError:
            raise AuthError({
                'code': 'invalid_claims',
                'description': 'Incorrect claims. Please, check the audience and issuer.'
            }, 401)
        except Exception:
            raise AuthError({
                'code': 'invalid_header',
                'description': 'Unable to parse authentication token.'
            }, 400)
    raise AuthError({
        'code': 'invalid_header',
                'description': 'Unable to find the appropriate key.'
    }, 400)


'''
@TODO implement @requires_auth(permission) decorator method
    @INPUTS
        permission: string permission (i.e. 'post:drink')

    it should use the get_token_auth_header method to get the token
    it should use the verify_decode_jwt method to decode the jwt
    it should use the check_permissions method validate claims and check the requested permission
    return the decorator which passes the decoded payload to the decorated method
'''


def requires_auth(permission=''):
    def requires_auth_decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = get_token_auth_header()
            try:
                payload = verify_decode_jwt(token)
            except:
                raise AuthError({
                    'code': "Unverifiable token",
                    'description': 'Token could not be verified'
                }, 400)
            check_permissions(permission, payload)
            return f(* args, **kwargs)

        return wrapper
    return requires_auth_decorator
