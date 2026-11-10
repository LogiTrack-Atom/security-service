#!/usr/bin/env python3
"""Regresión de renovación por Gateway/Nginx local, con credenciales de prueba en entorno.

Requiere S04_BASE_URL (http://localhost:puerto), S04_ADMIN_EMAIL y S04_ADMIN_PASSWORD.
No usa CookieJar: verifica la API; la aceptación de Secure/HttpOnly por el navegador se
prueba por separado. Tokens y cookies permanecen en memoria y no se imprimen.
"""
import json
import os
import sys
from http.cookies import SimpleCookie
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler


class NoRedirect(HTTPRedirectHandler):
    """Impide reenviar credenciales hacia redirecciones."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def main():
    """Comprueba atributos, CSRF, rotación/replay y logout sin guardar credenciales."""
    base = os.environ['S04_BASE_URL'].rstrip('/')
    url = urlsplit(base)
    if url.scheme != 'http' or url.hostname != 'localhost' or url.path or url.username or url.password or url.query or url.fragment:
        raise ValueError('Usar un origen HTTP localhost del laboratorio descartable.')
    prefix = '/applications/apisecurity/api/v1/auth'
    calls = assertions = 0
    opener = build_opener(NoRedirect())

    def check(value, message):
        nonlocal assertions
        assertions += 1
        if not value:
            raise AssertionError(message)

    def call(path, status, cookie=None, body=None, csrf=True, origin=True, method='POST'):
        nonlocal calls
        calls += 1
        headers = {'Accept': 'application/json'}
        if csrf:
            headers['X-LogiTrack-Session'] = '1'
        if origin:
            headers['Origin'] = base
        if cookie:
            headers['Cookie'] = cookie
        if body is not None:
            headers['Content-Type'] = 'application/json'
        req = Request(base + prefix + path, method=method, headers=headers,
                      data=None if body is None else json.dumps(body).encode())
        try:
            response = opener.open(req, timeout=30)
        except HTTPError as error:
            response = error
        with response:
            check(response.code == status, f'{method} auth{path}: HTTP {response.code}, esperado {status}')
            return response.headers, json.load(response) if status == 200 else None

    credentials = {'email': os.environ['S04_ADMIN_EMAIL'], 'password': os.environ['S04_ADMIN_PASSWORD']}
    headers, token = call('/session', 200, body=credentials)
    parsed = SimpleCookie(headers['Set-Cookie']); item = parsed['__Host-logitrack_refresh']
    check(item['secure'] and item['httponly'] and item['samesite'] == 'Strict' and item['path'] == '/' and not item['domain'], 'Atributos de cookie protegida')
    check(int(item['max-age']) > 0, 'Cookie vigente')
    check('no-store' in headers['Cache-Control'] and 'refresh' not in token, 'No caché ni refresh en JSON')
    first = '__Host-logitrack_refresh=' + item.value
    call('/me', 401, cookie=first, method='GET')
    headers, _ = call('/session/refresh', 403, cookie=first, csrf=False)
    check(headers.get('Set-Cookie') is None, 'CSRF no altera cookie')
    call('/session/refresh', 403, cookie=first, origin=False)
    headers, _ = call('/session/refresh', 200, cookie=first)
    second = headers['Set-Cookie'].split(';', 1)[0]
    check(second != first, 'Rotación de credencial')
    call('/session/refresh', 401, cookie=first)
    call('/session/refresh', 401, cookie=second)
    headers, _ = call('/session', 200, body=credentials)
    third = headers['Set-Cookie'].split(';', 1)[0]
    headers, _ = call('/session/logout', 204, cookie=third)
    check('Max-Age=0' in headers['Set-Cookie'], 'Logout elimina cookie')
    call('/session/refresh', 401, cookie=third)
    call('/session/logout', 204, cookie=third)
    print(json.dumps({'ok': True, 'requests_http': calls, 'aserciones': assertions,
                      'browser_cookie_acceptance': 'verificar por separado con navegador real'}, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, AssertionError) as error:
        print(str(error), file=sys.stderr); sys.exit(1)
    except Exception:
        print('Verificación incompleta; revisar laboratorio y configuración privada.', file=sys.stderr); sys.exit(1)
