#!/bin/env python3
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import base64
import os
import requests
import socket
import sys

URL = 'https://get.ishadowx.net/'

def ss_base64encode(bytes):
    c = base64.urlsafe_b64encode(bytes)
    return c

def ssr_base64encode(bytes):
    c = base64.urlsafe_b64encode(bytes)
    while c and c[-1] == b'='[0]:
        c = c[:-1]
    return c

def get_response(rss=False, ssr=True):
    req = requests.get(URL, headers={'User-Agent':
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:57.0) Gecko/20100101 Firefox/57.0'})
    data = req.content.decode('utf-8')
    resp = b''

    data = data.split('\n')
    i = 0
    count = 0

    while i < len(data):
        if 'IP Address:' in data[i]:
            ip = data[i].split('>')[2].split('<')[0]
            addr = ip
            if ip[-1].isalpha():
                ip = socket.gethostbyname(ip)
            port = data[i+1].split('>')[2].split('<')[0]
            password = data[i+3].split('>')[2].split('<')[0]
            method = data[i+5].split('>')[1].split(':')[1].split('<')[0]

            auth = 'origin'
            obfs = 'plain'
            if ssr:
                if 'auth' in data[i+6]:
                    auth = data[i+6].split('>')[1].split(' ')[0]
                    obfs = data[i+6].split('>')[1].split(' ')[1].split('<')[0]
            else:
                if 'auth' in data[i+6]:
                    i += 1
                    continue

            info = None
            if ssr:
                info = ip + ':' + port + ':' + auth + ':' + method + ':' + \
                       obfs + ':' + \
                       ssr_base64encode(password.encode('utf-8')).decode('utf-8') + '/' + \
                       '?obfsparam=&protoparam=&remarks=' + \
                       ssr_base64encode(addr.encode('utf-8')).decode('utf-8') + \
                       '&group=U1NS'
                info = b'ssr://' + ssr_base64encode(info.encode('utf-8'))
            else:
                info = method + ':' + password + '@' + ip + ':' + port
                info = b'ss://' + ss_base64encode(info.encode('utf-8'))

            resp += info + b'\n'
            count += 1
        i += 1

    if rss:
        resp = ('MAX=' + str(count) + '\n').encode('utf-8') + resp
        resp = ssr_base64encode(resp)

    return resp

def application(environ, start_response):
    resp = b''
    if environ['PATH_INFO'] == '/rss':
        resp = get_response(rss=True, ssr=True)
    elif environ['PATH_INFO'] == '/ssr':
        resp = get_response(rss=False, ssr=True)
    elif environ['PATH_INFO'] == '/ss':
        resp = get_response(rss=False, ssr=False)
    else:
        resp = b''

    if resp != b'':
        start_response('200 OK', [('Content-Length', str(len(resp)))])
    else:
        start_response('404 Not Found', [('Content-Length', '0')])

    yield resp

if __name__ == '__main__':
    path = '/'
    if len(sys.argv) > 1:
        path = sys.argv[1]
    for x in application({'PATH_INFO': path}, lambda x, y: None):
        sys.stdout.write(x.decode('utf-8'))
        sys.stdout.write('\n')
