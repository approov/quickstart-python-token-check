import http.server
import socketserver
import logging
import json
from http import HTTPStatus

from os import getenv
from dotenv import load_dotenv, find_dotenv
load_dotenv(find_dotenv(), override=True)

HOSTNAME = getenv('SERVER_HOSTNAME', '127.0.0.1')
HTTP_PORT = int(getenv('HTTP_PORT', '8002'))

class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(request):
        if request.path == '/':
            request.send_response(HTTPStatus.OK)
            request.send_header('Content-type', 'application/json')
            request.end_headers()
            request.wfile.write(json.dumps({"message": "Hello, World!"}).encode("utf-8"))
            return

        request.send_response(HTTPStatus.BAD_REQUEST)
        request.send_header('Content-type', 'application/json')
        request.end_headers()
        request.wfile.write(json.dumps({}).encode("utf-8"))

if __name__ == "__main__":
    try:
        logging.basicConfig(level=logging.DEBUG)
        logging.info('Server running at http://%s:%i', HOSTNAME, HTTP_PORT)
        socketserver.TCPServer.allow_reuse_address = True
        httpd = socketserver.TCPServer((HOSTNAME, HTTP_PORT), Handler)
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass

    httpd.server_close()
