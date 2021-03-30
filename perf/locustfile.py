import hashlib
import random
import time
import os
from urllib import parse
from locust import HttpUser, task, between
from dotenv import load_dotenv
load_dotenv()

email = os.getenv("EMAIL")
password = os.getenv("PASSWORD")
client_id = os.getenv("CLIENT_ID")
client_secret = os.getenv("CLIENT_SECRET")
redirect_uri = os.getenv("REDIRECT_URI")

# Use the system PRNG if possible
try:
    random = random.SystemRandom()
    using_sysrandom = True
except NotImplementedError:
    import warnings
    warnings.warn('A secure pseudo-random number generator is not available '
                  'on your system. Falling back to Mersenne Twister.')
    using_sysrandom = False


def get_random_string(length=32,
                      allowed_chars='abcdefghijklmnopqrstuvwxyz'
                                    'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'):
    """
    Returns a securely generated random string.
    The default length of 12 with the a-z, A-Z, 0-9 character set returns
    a 71-bit value. log_2((26+26+10)^12) =~ 71 bits

    see https://github.com/django/django/blob/0ed7d155635da9f79d4dd67e4889087d3673c6da/django/utils/crypto.py#L54
    """
    if not using_sysrandom:
        # This is ugly, and a hack, but it makes things better than
        # the alternative of predictability. This re-seeds the PRNG
        # using a value that is hard for an attacker to predict, every
        # time a random string is required. This may change the
        # properties of the chosen random sequence slightly, but this
        # is better than absolute predictability.
        random.seed(
            hashlib.sha256(
                ("%s%s%s" % (
                    random.getstate(),
                    time.time(),
                    '0722e978-b72e-4733-8c4e-bf86a3edc938')).encode('utf-8')
            ).digest())
    return ''.join(random.choice(allowed_chars) for i in range(length))


class WebsiteUser(HttpUser):
    wait_time = between(5, 9)

    @task
    def openid_configuration(self):
        self.client.get("/.well-known/openid-configuration")

    @task
    def webfinger(self):
        response = self.client.get("/.well-known/webfinger",
                                   params={
                                       'resource': self.client.base_url,
                                       'rel': 'http://openid.net/specs/connect/1.0/issuer'
                                   })

    @task(3)
    def login(self):
        state = get_random_string()
        nonce = get_random_string()
        self.client.get("/index.php/auth",
                        params={
                            "state": state,
                            "response_type": "code",
                            "redirect_uri": redirect_uri,
                            "scope": "openid profile email address phone",
                            "client_id": client_id,
                            "nonce": nonce
                        },
                        name="/index.php/auth?state=[state]&response_type=code&redirect_uri=[redirect_uri]&scope=openid profile email address phone&client_id=[client_id]&nonce=[nonce]")
        response = self.client.post("/index.php/login",
                                    data={
                                        "username":	email,
                                        "password":	password
                                    },
                                    allow_redirects=False)
        if (not response.is_redirect):
            raise Exception('Invalid response from login')
        redirect_url = response.headers['location']
        response_params = dict(parse.parse_qsl(
            parse.urlsplit(redirect_url).query))
        if (state != response_params['state']):
            raise Exception('Invalid state')

        code = response_params['code']

        response = self.client.post("/index.php/token",
                                    data={
                                        "grant_type": "authorization_code",
                                        "code": code,
                                        "redirect_uri": redirect_uri,
                                        # "client_id": client_id,
                                        # "client_secret": client_secret
                                    },
                                    auth=(client_id, client_secret))
        tokens = response.json()
        if "access_token" not in tokens:
            raise Exception('No access token')

        response = self.client.post("/index.php/validatetoken",
                                    data={
                                        "access_token": tokens['access_token'],
                                    },
                                    auth=(client_id, client_secret))
        token_response = response.json()
        if not token_response['active']:
            raise Exception('Access token invalid')

        response = self.client.post("/index.php/userinfo",
                                    data={
                                        "access_token": tokens['access_token'],
                                    },
                                    auth=(client_id, client_secret))
        userinfo = response.json()
        if  'sub' not in userinfo:
            raise Exception('UserInfo invalid')


if __name__ == '__main__':
    WebsiteUser().run()
