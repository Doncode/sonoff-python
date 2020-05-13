import threading
import time
import random
import string
import json
import logging

from websocket import WebSocketApp

logger = logging.getLogger(__name__)

class WebsocketListener(threading.Thread, WebSocketApp):
    def __init__(self, sonoff, on_message=None, on_error=None):
        self.__sonoff = sonoff

        threading.Thread.__init__(self)
        WebSocketApp.__init__(
            self, 
            f'wss://{self.__sonoff._wshost}:8080/api/ws',
            on_open=self.on_open,
            on_error=on_error,
            on_message=on_message,
            on_close=self.on_close
        )

        self.connected = False
        self.last_update = time.time()

    def on_open(self, *args):
        self.connected = True
        self.last_update = time.time()

        payload = {
            'action'    : "userOnline",
            'userAgent' : 'app',
            'version'   : 6,
            'nonce'     : ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(8)),
            'apkVersion': "1.8",
            'os'        : 'iOS',
            'at'        : self.__sonoff.get_bearer_token(),
            'apikey'    : self.__sonoff.get_user_apikey(),
            'ts'        : str(int(time.time())),
            'model'     : self.__sonoff.get_model(),
            'romVersion': self.__sonoff.get_romVersion(),
            'sequence'  : str(time.time()).replace('.','')
        }

        self.send(json.dumps(payload))

    def on_close(self, *args):
        logger.debug('websocket closed')
        self.connected = False

    def run_forever(self, sockopt=None, sslopt=None, ping_interval=0, ping_timeout=None):
        WebSocketApp.run_forever(
            self,
            sockopt=sockopt,
            sslopt=sslopt,
            ping_interval=ping_interval,
            ping_timeout=ping_timeout
        )
