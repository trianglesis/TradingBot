import json
import hashlib
import logging
import random
import time
from urllib import parse

import requests
import a_core.credentials as credentials

log = logging.getLogger("a_core.corelogger")


class BtcTradeUa(object):
    API_URL_V1 = "https://btc-trade.com.ua/api/"
    BASE = "https://btc-trade.com.ua/"
    API_URL_V2 = "https://btc-trade.com.ua/api/v2/"

    def __init__(self, *args, **kwargs):
        self.__nonce = int(time.time()) * 1000
        log.debug(f"Init args: {args} kwargs: {kwargs}")

    @staticmethod
    def random_order():
        Val = "my_randm" + str(random.randrange(1, 1000000000000000000))
        m = hashlib.sha256()
        m.update(Val.encode())
        return m.hexdigest()

    def __update_auth(self, result):
        self.__nonce = self.__nonce + 1

    @staticmethod
    def api_sign(private_key, body):
        m = hashlib.sha256()
        string = body + private_key
        m.update(string.encode('utf-8'))
        log.debug(f"STRING: {string.encode('utf-8')}")
        log.debug(f"SECRET: {m.hexdigest()}")
        return m.hexdigest()

    def make_header(self, raw_data, auth=True):
        custom_headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
            "public_key": credentials.btc_trade_ua_PUB,
            "api_sign": self.api_sign(credentials.btc_trade_ua_PRIV, raw_data),
        }
        log.debug(f"Headers composed: {custom_headers}")
        return custom_headers

    def save_token(self, token):
        token = dict(token)

    def post(self, url, raw_data=None, auth=True):
        r = requests.post(url,
                          data=raw_data,
                          headers=self.make_header(raw_data, auth),
                          verify=False
                          )
        if r.status_code not in [200]:
            log.error(f"Cannot POST: {url} STATUS: {r.status_code}: {r.text}")
        return r

    def get(self, url, raw_data, auth=False):
        r = requests.get(url,
                         params=raw_data,
                         headers=self.make_header(raw_data, auth),
                         verify=False
                         )
        if r.status_code not in [200]:
            log.error(f"Cannot GET: {url} STATUS: {r.status_code}: {r.text}")
        return r

    def run_auth(self, out_order_id=None):
        if out_order_id is None:
            out_order_id = self.random_order()

        url = self.API_URL_V1 + 'auth'
        params = {"out_order_id": out_order_id, "nonce": self.__nonce}
        raw_data = parse.urlencode(params)
        log.debug(f'POST URL: {url}')

        r = self.post(url, raw_data, auth=True)
        log.debug(f"STATUS CODE: {r.status_code}")
        self.__update_auth(r)
        r.json()
        log.debug(f"r.json(): {r.json()}")


BtcTradeUa().run_auth()
