# Copyright (C) 2015 by Arnaud Durand <arnaud.durand@protonmail.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

import re

from scrapy import log
from scrapy.utils.request import request_fingerprint


class TorProcess:

    def __init__(self, socks_port=9000, control_port=7000, index=0):
        print(" - Starting TOR Process...")
        self.socks_port = socks_port
        self.control_port = control_port
        self.tor_processes.append(stem.process.launch_tor_with_config(
            config={
                'SocksPort': str(self.socks_port),
                'ControlPort': str(self.control_port+index),
                'DataDirectory':'data/tor'+str(index),
                'PidFile':'tor'+str(index)+'.pid',
                },
            init_msg_handler = msg_handler,
            take_ownership = True,
            ))

    def newnym(self):
        print("[+] Changing IP Address... [%i]" % self.socks_port)
        start = time.time()
        controller = Controller.from_port(port = self.control_port)
        controller.authenticate()
        controller.signal(Signal.NEWNYM)
        time.sleep(controller.get_newnym_wait())
        end = time.time()
        print (end - start)

    def __unicode__(self):
        return unicode(proxy_address)

    @attribute
    def proxy_address(self):
        return '127.0.0.1:%i' % self.socks_port


class TorPool(object):
    def __init__(self, size=1):
        self.tor_processes = []
        self.base_socks_port = 9000
        self.base_control_port = 7000
        for i in xrange(size):
            tor_processes.append(TorProcess(base_socks_port=self.base_socks_port+i,
                                            base_control_port=self.base_control_port+i,
                                            port_index=i))

    def __getitem__(self, key):
        return self.tor_processes[key]

    def __len__(self):
        return len(tor_processes)


class TorProxy(object):

    def __init__(self, settings):
        pool_size = settings.get('TOR_POOL_SIZE')
        self.tor_pool = TorPool(size = pool_size)

    @classmethod
    def from_crawler(cls, crawler):
        return cls(crawler.settings)

    def process_request(self, request, spider):
        # Don't overwrite with a random one (server-side state for IP)
        if 'proxy' in request.meta:
            return
        tor_proc = self._request_tor_instance(request)
        if 'newnym' in request.meta:
            tor_proc.newnym()
        request.meta['proxy'] = tor_proc.proxy_address

    def process_exception(self, request, exception, spider):
        tor_proc = self._request_tor_instance(request)
        proxy = request.meta['proxy']
        log.msg('Failed proxy <%s>, %d proxies available' % (
                    tor_proc, len(self.tor_pool)))
        try:
            pass
        except ValueError:
            pass

    def _request_tor_instance(self, request):
        req_hash = request_fingerprint(request)
        proxy_idx = req_hash % self.pool_size
        return  self.tor_pool[proxy_idx]
