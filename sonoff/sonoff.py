# The domain of your component. Should be equal to the name of your component.
import logging
import time
import hmac
import hashlib
import random
import base64
import json
import socket
import requests
import re
import ssl

from datetime import timedelta
from sonoff.device_listener import WebsocketListener

SCAN_INTERVAL = timedelta(seconds=60)
HTTP_MOVED_PERMANENTLY, HTTP_BAD_REQUEST, HTTP_UNAUTHORIZED, HTTP_NOT_FOUND = 301,400,401,404

logger = logging.getLogger(__name__)

def gen_nonce(length=8):
    """Generate pseudorandom number."""
    return ''.join([str(random.randint(0, 9)) for i in range(length)])

class Sonoff():
    def __init__(self, username, password, api_region, user_apikey=None, bearer_token=None, grace_period=600):

        self._username      = username
        self._password      = password
        self._api_region    = api_region
        self._wshost        = None

        self._skipped_login = 0
        self._grace_period  = timedelta(seconds=grace_period)

        self._user_apikey   = user_apikey
        self._bearer_token  = bearer_token
        self._devices       = []
        self._ws            = None

        # app details
        self._app_version = '3.5.3'
        self._appid = 'oeVkj2lYFGnJu5XUtWisfW4utiN4u9Mq'
        self._model = 'iPhone10,6'
        self._os = 'iOS'
        self._rom_version = '11.1.2'
        self._version = '6'

        if user_apikey and bearer_token:
            self.do_reconnect()
        else:
            self.do_login()

    def do_reconnect(self):
        self._headers = {
            'Authorization' : 'Bearer ' + self._bearer_token,
            'Content-Type'  : 'application/json;charset=UTF-8'
        }

        try:
            # get the websocket host
            if not self._wshost:
                self.set_wshost()

            self.update_devices() # to get the devices list
        except:
            self.do_login()

    def do_login(self):
        import uuid

        # reset the grace period
        self._skipped_login = 0
        
        app_details = {
            'password'  : self._password,
            'version'   : '6',
            'ts'        : int(time.time()),
            'nonce'     : gen_nonce(15),
            'appid'     : 'oeVkj2lYFGnJu5XUtWisfW4utiN4u9Mq',
            'imei'      : str(uuid.uuid4()),
            'os'        : 'iOS',
            'model'     : 'iPhone10,6',
            'romVersion': '11.1.2',
            'appVersion': '3.5.3'
        }

        if re.match(r'[^@]+@[^@]+\.[^@]+', self._username):
            app_details['email'] = self._username
        else:
            app_details['phoneNumber'] = self._username

        decryptedAppSecret = b'6Nz4n0xA8s8qdxQf2GqurZj2Fs55FUvM'

        hex_dig = hmac.new(
            decryptedAppSecret, 
            str.encode(json.dumps(app_details)), 
            digestmod=hashlib.sha256).digest()
        
        sign = base64.b64encode(hex_dig).decode()

        self._headers = {
            'Authorization' : 'Sign ' + sign,
            'Content-Type'  : 'application/json;charset=UTF-8'
        }

        response = requests.post(
            f'https://{self._api_region}-api.coolkit.cc:8080/api/user/login', 
            headers=self._headers, 
            json=app_details
        ).json()

        # get a new region to login
        if 'error' in response and 'region' in response and response['error'] == HTTP_MOVED_PERMANENTLY:
            self._api_region  = response['region']

            logger.warning(f'Change api_region option to {self._api_region}')

            # re-login using the new localized endpoint
            self.do_login()
            return

        elif 'error' in response and response['error'] in [HTTP_NOT_FOUND, HTTP_BAD_REQUEST]:
            # (most likely) login with +86... phone number and region != cn
            if '@' not in self._username and self._api_region != 'cn':
                self._api_region    = 'cn'
                self.do_login()

            else:
                logger.error("Couldn't authenticate using the provided credentials!")

            return

        self._bearer_token  = response['at']
        self._user_apikey   = response['user']['apikey']
        self._headers.update({'Authorization' : 'Bearer ' + self._bearer_token})

        # get the websocket host
        if not self._wshost:
            self.set_wshost()

        self.update_devices() # to get the devices list 

    def set_wshost(self):
        response = requests.post(
            f'https://{self._api_region}-disp.coolkit.cc:8080/dispatch/app',
            headers=self._headers
        ).json()

        if 'error' in response and response['error'] == 0 and 'domain' in response:
            self._wshost = response['domain']
            logger.info(f'Found websocket address: {self._wshost}')
        else:
            raise Exception('No websocket domain')

    def is_grace_period(self):
        grace_time_elapsed = self._skipped_login * int(SCAN_INTERVAL.total_seconds()) 
        grace_status = grace_time_elapsed < int(self._grace_period.total_seconds())

        if grace_status:
            self._skipped_login += 1

        return grace_status

    def update_devices(self):

        # the login failed, nothing to update
        if not self._wshost:
            return []

        # we are in the grace period, no updates to the devices
        if self._skipped_login and self.is_grace_period():          
            logger.info("Grace period active")            
            return self._devices


        response = requests.get(
            f'https://{self._api_region}-api.coolkit.cc:8080/api/user/device?lang=en&apiKey=\
                {self._user_apikey}&getTags=1&appid=oeVkj2lYFGnJu5XUtWisfW4utiN4u9Mq',
            headers=self._headers
        ).json()

        if 'error' in response and response['error'] in [HTTP_BAD_REQUEST, HTTP_UNAUTHORIZED]:
            # @IMPROVE add maybe a service call / switch to deactivate sonoff component
            if self.is_grace_period():
                logger.warning("Grace period activated!")

                # return the current (and possible old) state of devices
                # in this period any change made with the mobile app (on/off) won't be shown in HA
                return self._devices

            logger.info("Re-login component")
            self.do_login()

        self._devices = response
        return self._devices

    def get_devices(self, force_update = False):
        if force_update: 
            return self.update_devices()

        return self._devices

    def get_device(self, deviceid):
        for device in self.get_devices():
            if 'deviceid' in device and device['deviceid'] == deviceid:
                return device

    def get_api_region(self):
        return self._api_region

    def get_bearer_token(self):
        return self._bearer_token

    def get_user_apikey(self):
        return self._user_apikey
    
    def get_model(self):
        return self._model

    def get_romVersion(self):
        return self._rom_version

    def wait_for_notice(self, deviceid, on_message, on_error):
        self.set_wshost()

        while True:
            logger.debug('(re)init websocket')

            self._ws = WebsocketListener(
                sonoff=self,
                on_message=on_message, 
                on_error=on_error
            )

            try:
                # 145 interval is defined by the first websocket response after login
                self._ws.run_forever(ping_interval=145)
            finally:
                self._ws.close()

    def _get_ws(self):
        """Check if the websocket is setup and connected."""
        try:
            create_connection
        except:
            from websocket import create_connection

        if self._ws is None:
            try:
                self._ws = create_connection(
                    f'wss://{self._wshost}:8080/api/ws',
                    timeout=10, 
                    sslopt={
                        "cert_reqs": ssl.CERT_NONE
                    }
                )

                payload = {
                    'action'    : "userOnline",
                    'userAgent' : 'app',
                    'version'   : 6,
                    'nonce'     : gen_nonce(15),
                    'apkVesrion': "1.8",
                    'os'        : 'ios',
                    'at'        : self.get_bearer_token(),
                    'apikey'    : self.get_user_apikey(),
                    'ts'        : str(int(time.time())),
                    'model'     : 'iPhone10,6',
                    'romVersion': '11.1.2',
                    'sequence'  : str(time.time()).replace('.','')
                }

                self._ws.send(json.dumps(payload))
                wsresp = self._ws.recv()
                # logger.error("open socket: %s", wsresp)

            except (socket.timeout, ConnectionRefusedError, ConnectionResetError):
                logger.error('failed to create the websocket')
                self._ws = None

        return self._ws
        
    def switch(self, new_state, deviceid, outlet=None):
        """Switch on or off."""

        # we're in the grace period, no state change
        if self._skipped_login:
            logger.info("Grace period, no state change")
            return (not new_state)

        self._ws = self._get_ws()
        
        if not self._ws:
            logger.warning('invalid websocket, state cannot be changed')
            return (not new_state)

        # convert from True/False to on/off
        if isinstance(new_state, (bool)):
            new_state = 'on' if new_state else 'off'

        device = self.get_device(deviceid)

        if outlet is not None:
            logger.debug(
                f"Switching `{device['deviceid']} - {device['name']}` on outlet {(outlet+1)} to state: {new_state}"
            )
        else:
            logger.debug(f"Switching `{deviceid}` to state: {new_state}")

        if not device:
            logger.error('unknown device to be updated')
            return False

        # the payload rule is like this:
        #   normal device (non-shared) 
        #       apikey      = login apikey (= device apikey too)
        #
        #   shared device
        #       apikey      = device apikey
        #       selfApiKey  = login apikey (yes, it's typed corectly selfApikey and not selfApiKey :|)

        if outlet is not None:
            params = { 'switches' : device['params']['switches'] }
            params['switches'][outlet]['switch'] = new_state

        else:
            params = { 'switch' : new_state }

        payload = {
            'action'        : 'update',
            'userAgent'     : 'app',
            'params'        : params,
            'apikey'        : device['apikey'],
            'deviceid'      : str(deviceid),
            'sequence'      : str(time.time()).replace('.',''),
            'controlType'   : device['params']['controlType'] if 'controlType' in device['params'] else 4,
            'ts'            : 0
        }

        # this key is needed for a shared device
        if device['apikey'] != self.get_user_apikey():
            payload['selfApikey'] = self.get_user_apikey()

        self._ws.send(json.dumps(payload))
        wsresp = self._ws.recv()
        # logger.debug("switch socket: %s", wsresp)
        
        self._ws.close() # no need to keep websocket open (for now)
        self._ws = None

        # set also te pseudo-internal state of the device until the real refresh kicks in
        for idx, device in enumerate(self._devices):
            if device['deviceid'] == deviceid:
                if outlet is not None:
                    self._devices[idx]['params']['switches'][outlet]['switch'] = new_state
                else:
                    self._devices[idx]['params']['switch'] = new_state


        # @TODO add some sort of validation here, maybe call the devices status 
        # only IF MAIN STATUS is done over websocket exclusively

        return new_state
