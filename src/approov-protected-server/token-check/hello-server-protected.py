import http.server
import socketserver
import logging
import json
import base64
import jwt # https://github.com/jpadilla/pyjwt/
from http import HTTPStatus

from os import getenv
from dotenv import load_dotenv, find_dotenv
load_dotenv(find_dotenv(), override=True)

HOSTNAME = getenv('SERVER_HOSTNAME', '127.0.0.1')
HTTP_PORT = int(getenv('HTTP_PORT', '8002'))

# Token secret value obtained with the Approov CLI tool:
#  - approov secret -get
approov_base64_secret = getenv('APPROOV_BASE64_SECRET')

if approov_base64_secret == None:
    raise ValueError("Missing the value for environment variable: APPROOV_BASE64_SECRET")

APPROOV_SECRET = base64.b64decode(approov_base64_secret)

# @link https://approov.io/docs/latest/approov-usage-documentation/#backend-integration
def verifyApproovToken(request):
    approov_token = request.headers.get("Approov-Token")

    # If we didn't find a token, then reject the request.
    if approov_token == "":
        # You may want to add some logging here.
        return None

    try:
        # Decode the Approov token explicitly with the HS256 algorithm to avoid
        # the algorithm None attack.
        approov_token_claims = jwt.decode(approov_token, APPROOV_SECRET, algorithms=['HS256'])
        return approov_token_claims
    except jwt.ExpiredSignatureError as e:
        # You may want to add some logging here.
        return None
    except jwt.InvalidTokenError as e:
        # You may want to add some logging here.
        return None


class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(request):
        approov_token_claims = verifyApproovToken(request)

        if approov_token_claims == None:
            request.send_response(HTTPStatus.UNAUTHORIZED)
            request.send_header('Content-type', 'application/json')
            request.end_headers()
            request.wfile.write(json.dumps({}).encode("utf-8"))
            return

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
