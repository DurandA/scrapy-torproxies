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

import os
import re
import socket
import time

import socks
import stem.connection
import stem.process
import stem.socket
from scrapy import log
from scrapy.core.downloader.handlers.http11 import (HTTP11DownloadHandler,
                                                    ScrapyAgent)
from scrapy.core.downloader.webclient import _parse
from scrapy.utils.request import request_fingerprint
from scrapy.xlib.tx import TCP4ClientEndpoint
from stem import Signal
from stem.control import Controller
from stem.util import term
from twisted.internet import reactor
from txsocksx.http import SOCKS5Agent


class Socks5DownloadHandler(HTTP11DownloadHandler):
    """
    https://gist.github.com/cydu/8a4b9855c5e21423c9c5
    author: cydu<root@cydu.net>
    """

    def download_request(self, request, spider):
        """Return a deferred for the HTTP download"""
        agent = ScrapySocks5Agent(contextFactory=self._contextFactory, pool=self._pool)
        return agent.download_request(request)


class ScrapySocks5Agent(ScrapyAgent):
    """
    https://gist.github.com/cydu/8a4b9855c5e21423c9c5
    author: cydu<root@cydu.net>
    """

    def _get_agent(self, request, timeout):
        bindAddress = request.meta.get('bindaddress') or self._bindAddress
        proxy = request.meta.get('proxy')
        if proxy:
            _, _, proxyHost, proxyPort, proxyParams = _parse(proxy)
            _, _, host, port, proxyParams = _parse(request.url)
            proxyEndpoint = TCP4ClientEndpoint(reactor, proxyHost, proxyPort,
                                timeout=timeout, bindAddress=bindAddress)
            agent = SOCKS5Agent(reactor, proxyEndpoint=proxyEndpoint)
            return agent
        return self._Agent(reactor, contextFactory=self._contextFactory,
            connectTimeout=timeout, bindAddress=bindAddress, pool=self._pool)


class TorProcess:

    def __init__(self, socks_port=9000, control_port=7000, index=0):
        print(" - Starting TOR Process...")
        self.socks_port = socks_port
        self.control_port = control_port
        stem.process.launch_tor_with_config(
            config={
                'SocksPort': str(self.socks_port),
                'ControlPort': str(self.control_port+index),
                'DataDirectory':'data/tor'+str(index),
                'PidFile':'tor'+str(index)+'.pid',
                },
            init_msg_handler = self.msg_handler,
            take_ownership = True,
            )
        self.nym_updated_on = time.time()

    def msg_handler(self, line):
        if("Bootstrapped " in line):
            print(line)

    def newnym(self):
        print("[+] Changing IP Address... [%i]" % self.socks_port)
        start = time.time()
        controller = Controller.from_port(port = self.control_port)
        controller.authenticate()
        controller.signal(Signal.NEWNYM)
        time.sleep(controller.get_newnym_wait())
        end = time.time()
        print (end - start)
        self.nym_updated_on = time.time()

    def __unicode__(self):
        return unicode(proxy_address)

    @property
    def proxy_address(self):
        return '127.0.0.1:%i' % self.socks_port


class TorPool(object):

    def __init__(self, size=1):
        self.tor_processes = []
        self.base_socks_port = 9000
        self.base_control_port = 7000
        for i in range(size):
            self.tor_processes.append(TorProcess(
                        socks_port=self.base_socks_port+i,
                        control_port=self.base_control_port+i,
                        index=i))

    def __getitem__(self, key):
        return self.tor_processes[key]

    def __len__(self):
        return len(self.tor_processes)


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
            if request.meta['newnym'] > tor_proc.nym_updated_on:
                tor_proc.newnym()
        #print('prox_addr: %s' % tor_proc.proxy_address)
        request.meta['proxy'] = 'socks5://%s' % tor_proc.proxy_address

    # def process_exception(self, request, exception, spider):
    #     tor_proc = self._request_tor_instance(request)
    #     proxy = request.meta['proxy']
    #     log.msg('Failed proxy <%s>, %d proxies available' % (
    #                 tor_proc, len(self.tor_pool)))
    #     try:
    #         pass
    #     except ValueError:
    #         pass

    def _request_tor_instance(self, request):
        fingerprint = request_fingerprint(request)
        proxy_idx = int(fingerprint, 16) % len(self.tor_pool)
        return self.tor_pool[proxy_idx]
