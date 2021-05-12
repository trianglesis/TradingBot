# -*- coding: utf-8 -*-

import requests
import hashlib
import random
import urllib
import logging
import traceback
import time
import base64
import struct
import hmac
import sys
# Enabling debugging at http.client level (requests->urllib3->http.client)
# you will see the REQUEST, including HEADERS and DATA,
# and RESPONSE with HEADERS but without DATA.
# the only thing missing will be the response.body which is not logged.
try: # for Python 3
    from http.client import HTTPConnection
except ImportError:
    from httplib import HTTPConnection
    
class AuthFailed(Exception):
    pass
    

class BtcTradeUA(object):

    API_URL_V1 = "https://btc-trade.com.ua/api/"
    BASE = "https://btc-trade.com.ua/"
    API_URL_V2 = "https://btc-trade.com.ua/api/v2/"

    def __init__(self, *args, **kwargs):
        print kwargs
        self.__public_key = kwargs.get("public_key")
        self.__private_key = kwargs.get("private_key")
        self.__f2a_key =  kwargs.get("f2a_key")
        self.__nonce = kwargs.get("nonce", int(time.time())*1000)
        self.__verbosity = kwargs["verbose"]
        print self.__verbosity
        if self.__verbosity:
            HTTPConnection.debuglevel = 1
            logging.basicConfig()
            # you need to initialize logging, otherwise you will not
            # see anything from requests
            logging.getLogger().setLevel(logging.DEBUG)
            requests_log = logging.getLogger("requests.packages.urllib3")
            requests_log.setLevel(logging.DEBUG)
            requests_log.propagate = True

        
        self.__version = kwargs.get("version", 1)
        self.__authenticated = False
        if self.__version == 1:
            self.__end_points = {}
            self.__generate_end_points_v1()
        else:
            raise Exception("V2 doesn't supported yet")

    @staticmethod
    def random_order():
        Val = "my_randm" + str(random.randrange(1, 1000000000000000000))
        m = hashlib.sha256()
        m.update(Val)
        return m.hexdigest()
            
    def __get_request(self,  url, payload=None, auth=False):

        custom_headers = None
        if auth:
            custom_headers = {
                "public_key": self.__public_key,
                "api_sign" :
                    BtcTradeUA.make_api_sign(self.__private_key, payload)
            }
        
        result = requests.get(url, params=payload,
                              headers=custom_headers, verify=False)
        if result.status_code not in (200,):
            if self.__verbosity:
                print(result.text)
                traceback.print_exc()
            raise Exception("Bad status response")
        return result.json()


    def __post_request(self, url, payload=None, auth=True, auth2fa=False):
        custom_headers = None
        if auth:
            custom_headers = {
                "Accept":"application/json",
                "Content-Type": "application/x-www-form-urlencoded",
                "public_key": self.__public_key,
                "api_sign" :
                    BtcTradeUA.make_api_sign(self.__private_key, payload)
            }
        if auth and auth2fa :
            Time = time.time() 
            tm = int(Time / 30)
            secret = base64.b32decode(self.__f2a_key)
            b = struct.pack(">q", tm)
            
            # generate HMAC-SHA1 from timestamp based on secret key
            hm = hmac.HMAC(secret, b, hashlib.sha1).digest()
            # extract 4 bytes from digest based on LSB
            offset = ord(hm[-1]) & 0x0F
            truncatedHash = hm[offset:offset+4]
            # get the code from it
            code = struct.unpack(">L", truncatedHash)[0]
            code &= 0x7FFFFFFF
            code %= 1000000
            code = "%06d" % code
            custom_headers["security_password"] = code
            if self.__verbosity:
                print "setup %i wih  %s" % (tm, code)
                
        

        result = requests.post(url,  data=payload,
                               headers=custom_headers,
                               verify=False)
                               
        if result.status_code not in (200,):
            if self.__verbosity:
                print "Response"
                print "="*128
                print result.text
                traceback.print_exc()
            raise Exception("Bad status response")
        try:
           return result.json()
        except:
            print result.text
            raise Exception("Bad status response")
            

    @staticmethod
    def make_api_sign(private_key, body):
        m = hashlib.sha256()
        m.update(body + private_key)
        return m.hexdigest()

    def __update_auth(self, result):
        self.__nonce = self.__nonce + 1
    
    def sell(self, price, amount, market="btc_uah",  out_order_id=None):
        if out_order_id is None:
            out_order_id = BtcTradeUA.random_order()

        url = self.__end_points["sell"]+ market  +"?is_api=1"
        params = {"out_order_id": out_order_id, "nonce": self.__nonce, "count": amount, "price": price}
        raw_data = urllib.urlencode(params)
        result = self.__post_request(url, raw_data, auth=True)
        self.__update_auth(result)
        return result

    def buy(self, price, amount, market="btc_uah", out_order_id=None):
        if out_order_id is None:
            out_order_id = BtcTradeUA.random_order()

        url = self.__end_points["buy"]+ market  +"?is_api=1"
        params = {"out_order_id": out_order_id, "nonce": self.__nonce, "count": amount, "price": price}
        raw_data = urllib.urlencode(params)
        result = self.__post_request(url, raw_data, auth=True)
        self.__update_auth(result)
        return result



    def bid(self, market="btc_uah", amount=1, out_order_id=None):
        if out_order_id is None:
            out_order_id = BtcTradeUA.random_order()

        url = self.__end_points["bid"]+ market  +"?is_api=1&amount="+str(amount)
        params = {"out_order_id": out_order_id, "nonce": self.__nonce}
        raw_data = urllib.urlencode(params)
        result = self.__post_request(url, raw_data, auth=True)
        self.__update_auth(result)
        return result
       
    def ask(self, market="btc_uah", amount=1, out_order_id=None):
        if out_order_id is None:
            out_order_id = BtcTradeUA.random_order()

        url = self.__end_points["ask"]+ market +"?is_api=1&amount="+str(amount)
        params = {"out_order_id": out_order_id, "nonce": self.__nonce}
        raw_data = urllib.urlencode(params)
        result = self.__post_request(url, raw_data, auth=True)
        self.__update_auth(result)
        return result 
      
    def balance(self, out_order_id=None):
        if out_order_id is None:
            out_order_id = BtcTradeUA.random_order()

        url = self.__end_points["balance"]+ "?is_api=1"
        params = {"out_order_id": out_order_id, "nonce": self.__nonce}
        raw_data = urllib.urlencode(params)
        result = self.__post_request(url, raw_data, auth=True)
        self.__update_auth(result)
        return result       



    def my_orders(self, market_name="btc_uah" ,out_order_id=None):
        if out_order_id is None:
            out_order_id = BtcTradeUA.random_order()

        url = self.__end_points["my_orders"] + market_name
        params = {"out_order_id": out_order_id, "nonce": self.__nonce}
        raw_data = urllib.urlencode(params)
        result = self.__post_request(url, raw_data, auth=True)
        self.__update_auth(result)
        return result  
     
    # deprecated 
    def auth(self, out_order_id=None):
        if out_order_id is None:
            out_order_id = BtcTradeUA.random_order()

        url = self.__end_points["auth"]
        params = {"out_order_id": out_order_id, "nonce": self.__nonce}
        raw_data = urllib.urlencode(params)
        result = self.__post_request(url, raw_data, auth=True)
        self.__update_auth(result)        
        return result        

        
    def my_deals(self, market="btc_uah", out_order_id=None):
        if out_order_id is None:
            out_order_id = BtcTradeUA.random_order()

        url = self.__end_points["my_deals"] + market
        params = {"out_order_id": out_order_id, "nonce": self.__nonce}
        raw_data = urllib.urlencode(params)
        result = self.__post_request(url, raw_data, auth=True)
        self.__update_auth(result)
        return result        

    def deals(self, market="btc_uah"):
        url = self.__end_points["deals"] + market
        result = self.__get_request(url, auth=False)
        return result
    

    def order_remove(self, order_id, out_order_id=None):
        if out_order_id is None:
            out_order_id = BtcTradeUA.random_order()

        url = self.__end_points["remove"] + "/"+ str(order_id)
        params = {"out_order_id": out_order_id, "nonce": self.__nonce}
        raw_data = urllib.urlencode(params)
        result = self.__post_request(url, raw_data, auth=True, auth2fa=False)
        self.__update_auth(result)
        return result
    
    
    def order_move(self, order_id, price ,out_order_id=None):
        if out_order_id is None:
            out_order_id = BtcTradeUA.random_order()

        url = self.__end_points["move"] + "/"+ str(order_id)+ "/" + price
        params = {"out_order_id": out_order_id, "nonce": self.__nonce}
        raw_data = urllib.urlencode(params)
        result = self.__post_request(url, raw_data, auth=True, auth2fa=False)
        self.__update_auth(result)
        return result

    
    

    def buy_list(self, market="btc_uah"):
        url = self.__end_points["buy_list"] + market
        result = self.__get_request(url, auth=False)
        return result

    def sell_list(self, market="btc_uah"):
        url = self.__end_points["sell_list"] + market
        result = self.__get_request(url, auth=False)
        return result
    
    def markets(self):
        url = self.__end_points["markets"]
        res = self.__get_request(url, auth=False)
        result = []
        for item in res["prices"]:
            market = item["type"].replace("_top_price","")
            result.append((market, item["price"]))
        return result
    
    def invoice_status(self, order):
        
        url = self.__end_points["checkout_status"]
        params = { "nonce": self.__nonce , "order": order}
        
        raw_data = urllib.urlencode(params)
        result = self.__post_request(url, raw_data, auth=True)
        self.__update_auth(result)
        return result
    
    
    def invoice(self, params):
        url = self.__end_points["checkout"]
        if not params.has_key("order") or  params["order"] is None:
            params["order"] = BtcTradeUA.random_order()
        params["nonce"] = self.__nonce
        url = self.__end_points["checkout"]
        new_params = {}
        for k, v in params.iteritems():
            new_params[k] = unicode(v).encode('utf-8')
        raw_data = urllib.urlencode(new_params)
        result = self.__post_request(url, raw_data, auth=True)
        self.__update_auth(result)
        return result
    
    def address(self, currency="BTC", out_order_id=None):
        if out_order_id is None:
            out_order_id = BtcTradeUA.random_order()

        url = self.__end_points["address"]+ currency + "?is_api=1"
        params = {"out_order_id": out_order_id, "nonce": self.__nonce}
        raw_data = urllib.urlencode(params)
        result = self.__post_request(url, raw_data, auth=True)
        self.__update_auth(result)
        return result
    
    
    def send(self, currency, wallet, amnt, payment_id=None, out_order_id=None):
        if out_order_id is None:
            out_order_id = BtcTradeUA.random_order()

        url = self.__end_points["checkout_send"]
        params = {"out_order_id": out_order_id, "payment_id": payment_id, "nonce": self.__nonce, "currency": currency, "wallet": wallet, "amnt": amnt}
        raw_data = urllib.urlencode(params)
        result = self.__post_request(url, raw_data, auth=True, auth2fa=True)
        self.__update_auth(result)
        return result
    
    def send_status(self, ref, out_order_id=None):
        if out_order_id is None:
            out_order_id = BtcTradeUA.random_order()

        url = self.__end_points["send_status"]
        params = {"out_order_id": out_order_id, "nonce": self.__nonce, "ref": ref}
        raw_data = urllib.urlencode(params)
        result = self.__post_request(url, raw_data, auth=True, auth2fa=True)
        self.__update_auth(result)
        return result
    
    
    def __generate_end_points_v1(self):
        self.__end_points["auth"] = BtcTradeUA.API_URL_V1 + "auth"
        self.__end_points["sell_list"] = BtcTradeUA.API_URL_V1 + "trades/sell/"
        self.__end_points["buy_list"] = BtcTradeUA.API_URL_V1 + "trades/buy/"
        self.__end_points["ask"] = BtcTradeUA.API_URL_V1 + "ask/"
        self.__end_points["bid"] = BtcTradeUA.API_URL_V1 + "bid/"
        self.__end_points["buy"] = BtcTradeUA.API_URL_V1 + "buy/"
        self.__end_points["sell"] = BtcTradeUA.API_URL_V1 + "sell/"
        self.__end_points["remove"] = BtcTradeUA.API_URL_V1 + "remove/order/"
        self.__end_points["move"] = BtcTradeUA.API_URL_V1 + "move/order/"

        self.__end_points["status"] = BtcTradeUA.API_URL_V1 + "order/status/"
        self.__end_points["deals"] = BtcTradeUA.API_URL_V1 + "deals"
        self.__end_points["my_deals"] = BtcTradeUA.API_URL_V1 + "my_deals"
        self.__end_points["my_orders"] = BtcTradeUA.API_URL_V1 +"my_orders"
        self.__end_points["balance"] = BtcTradeUA.API_URL_V1 +"balance"
        self.__end_points["markets"] =  BtcTradeUA.API_URL_V1 +"market_prices"
        self.__end_points["checkout"] =  BtcTradeUA.BASE +"checkout/invoice"
        self.__end_points["checkout_status"] =  BtcTradeUA.BASE +"checkout/status"
        self.__end_points["checkout_send"] =  BtcTradeUA.BASE +"checkout/send"
        self.__end_points["send_status"] =  BtcTradeUA.BASE +"checkout/send/status"
        self.__end_points["address"] =  BtcTradeUA.BASE +"finance/crypto_currency/"


    #
        
    #(r'/api/buy/([\w]+)', CommonRequestHandlerOneParamNonThread,
#dict(callable_object=buy, name='buy')),
    #(r'/api/ask/([\w]+)', CommonRequestHandlerOneParamNonThread,
#dict(callable_object=ask, name='ask')),
    #(r'/api/bid/([\w]+)', CommonRequestHandlerOneParamNonThread,
#dict(callable_object=bid, name='bid')),
    #(r'/api/sell/([\w]+)', CommonRequestHandlerOneParamNonThread,
#dict(callable_object=sell, name='sell')),
    #(r'/api/remove/order/([\w]+)', CommonRequestHandlerOneParam,
#dict(callable_object=remove_order,
  
 #(r'/api/my_orders/([\w]+)', CommonRequestHandlerOneParam,
#dict(callable_object=my_orders,

#name='my_orders')),
    #(r'/api/order/status/([\w]+)', CommonRequestHandlerOneParam,
#dict(callable_object=order_status,

#name='order_status')),
    #(r'/api/deals/([\w]+)', CommonRequestHandlerOneParam,
#dict(callable_object=deal_list,

#name='deal_list')),
    #(r'/api/balance', CommonRequestHandler, dict(callable_object=user_balance,
                                                 #name='user_balance')),
    #(r'/api/my_deals/([\w]+)', CommonRequestHandlerOneParam,
#dict(callable_object=my_closed_orders,
#url("checkout/invoice", 'checkout.api.checkout', name="invoice"), 
#url("checkout/status/(\w+)$", 'checkout.api.check_status', name="invoice_status"),

        

        

if __name__ == '__main__':
    print sys.argv
    api_object = BtcTradeUA(public_key =sys.argv[1],
            private_key=sys.argv[2],
            f2a_key ="" ,
            verbose=True
            )
    print api_object.balance()
