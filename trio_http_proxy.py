#!/usr/bin/env python3

# Copyright 2018-2019 Joshua Bronson. All Rights Reserved.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# MitM HTTP proxy using Trio. Use an HTTPS certificate to capture and
# manipulate requests.
# Before using it, run mitmproxy to create the certificate on your machine.
#
# WARNING: This script has a memory leak. Do not use it in production.

import os
import ssl
from contextvars import ContextVar
from functools import partial
from io import DEFAULT_BUFFER_SIZE
from itertools import count
from os import getenv
from textwrap import indent
from traceback import format_exc

import h11
import trio
from mitmproxy.certs import CertStore
from mitmproxy.options import CONF_BASENAME
from trio import SSLStream

DEFAULT_PORT = 5000
PORT = int(getenv('PORT', DEFAULT_PORT))
OK_CONNECT_PORTS = {443, 8443}

prn = partial(print, end='')
indented = partial(indent, prefix='  ')
decoded_and_indented = lambda some_bytes: indented(some_bytes.decode())

CV_CLIENT_STREAM = ContextVar('client_stream', default=None)
CV_DEST_STREAM = ContextVar('dest_stream', default=None)
CV_PIPE_FROM = ContextVar('pipe_from', default=None)
TMP_DIR = '/tmp'
CERT_STORE_CONFIG_DIR = '~/.mitmproxy/'
CERT_STORE_PRIVATE_KEY = '~/.mitmproxy/mitmproxy-ca.pem'

certstore = CertStore.from_store(
    path=os.path.expanduser(CERT_STORE_CONFIG_DIR),
    basename=CONF_BASENAME,
    key_size=2048,
    passphrase=None,
)
cert_key: str = os.path.expanduser(CERT_STORE_PRIVATE_KEY)


def get_cert_path(server_hostname: str) -> str:
    cert_path = os.path.join(TMP_DIR, f'{server_hostname}.pem')
    if os.path.lexists(cert_path):
        return cert_path
    altnames = [server_hostname]
    organization = 'Meta-Proxy'
    cert = certstore.get_cert(altnames[0], altnames, organization)
    pem_cert = cert.cert.to_pem()
    cert_path = os.path.join(TMP_DIR, f'{server_hostname}.pem')
    with open(cert_path, 'wb') as f:
        f.write(pem_cert)
    return cert_path


async def http_proxy(client_stream, _nextid=count(1).__next__):
    client_stream.id = _nextid()
    CV_CLIENT_STREAM.set(client_stream)
    async with client_stream:
        try:
            dest_stream, server_hostname = await tunnel(client_stream)

            context = ssl.SSLContext()
            context.load_cert_chain(get_cert_path(server_hostname), cert_key)
            https_client_stream = SSLStream(client_stream, context, server_hostname=server_hostname, server_side=True)

            async with https_client_stream, dest_stream, trio.open_nursery() as nursery:
                nursery.start_soon(pipe, https_client_stream, dest_stream)
                nursery.start_soon(pipe, dest_stream, https_client_stream)
        except Exception:
            log(f'\n{indented(format_exc())}')


async def start_server(server=http_proxy, port=PORT):
    print(f'* Starting {server.__name__} on port {port or "(OS-selected port)"}...')
    try:
        await trio.serve_tcp(server, port)
    except KeyboardInterrupt:
        print('\nGoodbye for now.')


async def tunnel(client_stream):
    """Given a stream from a client containing an HTTP CONNECT request,
    open a connection to the destination server specified in the CONNECT request,
    and notify the client when the end-to-end connection has been established.
    Return the destination stream and the corresponding host.
    """
    desthost, destport = await process_as_connect_request(client_stream)
    log(f'Got CONNECT request for {desthost}:{destport}, connecting...')
    dest_stream = await trio.open_ssl_over_tcp_stream(desthost, destport)
    dest_stream.host = desthost
    dest_stream.port = destport
    CV_DEST_STREAM.set(dest_stream)
    log(f'Connected to {desthost}, sending 200 to client...')
    await client_stream.send_all(b'HTTP/1.1 200 Connection established\r\n\r\n')
    log('Sent 200 to client, tunnel established.')
    return dest_stream, desthost


async def process_as_connect_request(stream, bufmaxsz=DEFAULT_BUFFER_SIZE, maxreqsz=16384):
    """Read a stream expected to contain a valid HTTP CONNECT request to desthost:destport.
    Parse and return the destination host. Validate (lightly) and raise if request invalid.
    See https://tools.ietf.org/html/rfc7231#section-4.3.6 for the CONNECT spec.
    """
    # TODO: give client 'bad request' errors on assertion failure
    log(f'Reading...')
    h11_conn = h11.Connection(our_role=h11.SERVER)
    total_bytes_read = 0
    while (h11_nextevt := h11_conn.next_event()) == h11.NEED_DATA:
        bytes_read = await stream.receive_some(bufmaxsz)
        total_bytes_read += len(bytes_read)
        assert total_bytes_read < maxreqsz, f'Request did not fit in {maxreqsz} bytes'
        h11_conn.receive_data(bytes_read)
    assert isinstance(h11_nextevt, h11.Request), f'{h11_nextevt=} is not a h11.Request'
    assert h11_nextevt.method == b'CONNECT', f'{h11_nextevt.method=} != CONNECT'
    desthost, _, destport = h11_nextevt.target.partition(b':')
    destport = int(destport.decode())
    assert destport in OK_CONNECT_PORTS, f'{destport=} not in {OK_CONNECT_PORTS}'
    return desthost.decode(), destport


async def pipe(from_stream, to_stream, bufmaxsz=DEFAULT_BUFFER_SIZE):
    CV_PIPE_FROM.set(from_stream)
    async for chunk in from_stream:
        await to_stream.send_all(chunk)
        log(f'Forwarded {len(chunk)} bytes')
    log(f'Pipe finished')


def log(*args, **kw):
    client_stream = CV_CLIENT_STREAM.get()
    if client_stream:
        prn(f'[conn{client_stream.id}')
        dest_stream = CV_DEST_STREAM.get()
        if dest_stream:
            direction = '<>'
            pipe_from = CV_PIPE_FROM.get()
            if pipe_from:
                direction = '->' if pipe_from is client_stream else '<-'
            prn(f' {direction} {dest_stream.host}')
        prn('] ')
    print(*args, **kw)


if __name__ == '__main__':
    trio.run(start_server)
