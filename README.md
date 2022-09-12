# Approov QuickStart - Python Token Check

[Approov](https://approov.io) is an API security solution used to verify that requests received by your backend services originate from trusted versions of your mobile apps.

This repo implements the Approov server-side request verification code in Python (framework agnostic), which performs the verification check before allowing valid traffic to be processed by the API endpoint.


## Approov Integration Quickstart

The quickstart was tested with the following Operating Systems:

* Ubuntu 20.04
* MacOS Big Sur
* Windows 10 WSL2 - Ubuntu 20.04

First, setup the [Approov CLI](https://approov.io/docs/latest/approov-installation/index.html#initializing-the-approov-cli).

Now, register the API domain for which Approov will issues tokens:

```bash
approov api -add api.example.com
```

Next, enable your Approov `admin` role with:

```bash
eval `approov role admin`
````

For the Windows powershell:

```bash
set APPROOV_ROLE=admin:___YOUR_APPROOV_ACCOUNT_NAME_HERE___
```

Now, get your Approov Secret with the [Approov CLI](https://approov.io/docs/latest/approov-installation/index.html#initializing-the-approov-cli):

```bash
approov secret -get base64
```

Next, add the [Approov secret](https://approov.io/docs/latest/approov-usage-documentation/#account-secret-key-export) to your project `.env` file:

```env
APPROOV_BASE64_SECRET=approov_base64_secret_here
```

Now, add to your `requirements.txt` file the [JWT dependency](https://github.com/jpadilla/pyjwt/):

```bash
PyJWT==1.7.1 # update the version to the latest one
```

Next, you need to install the dependencies:

```bash
pip3 install -r requirements.txt
```

Next, in your code require the [JWT dependency](https://github.com/jpadilla/pyjwt/):

```python
import jwt
```

Now, read the Approov secret from the environment and put it into a variable:

```python
from os import getenv
from dotenv import load_dotenv, find_dotenv
load_dotenv(find_dotenv(), override=True)

approov_base64_secret = getenv('APPROOV_BASE64_SECRET')

if approov_base64_secret == None:
    raise ValueError("Missing the value for environment variable: APPROOV_BASE64_SECRET")

APPROOV_SECRET = base64.b64decode(approov_base64_secret)
```

Next, verify the Approov token:

```python
def verifyApproovToken(request):
    approov_token = request.headers.get("Approov-Token")

    # If we didn't find a token, then reject the request, because it didn't come
    # from a genuine and unmodified version of your mobile app.
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
```

Finally, invoke the check before your API endpoints declaration to protect them with the Approov token check:

```python
approov_token_claims = verifyApproovToken(request)

if approov_token_claims == None:
    request.send_response(HTTPStatus.UNAUTHORIZED)
    request.send_header('Content-type', 'application/json')
    request.end_headers()
    request.wfile.write(json.dumps({}).encode("utf-8"))
    return
```

Not enough details in the bare bones quickstart? No worries, check the [detailed quickstarts](QUICKSTARTS.md) that contain a more comprehensive set of instructions, including how to test the Approov integration.


## More Information

* [Approov Overview](OVERVIEW.md)
* [Detailed Quickstarts](QUICKSTARTS.md)
* [Examples](EXAMPLES.md)
* [Testing](TESTING.md)

### System Clock

In order to correctly check for the expiration times of the Approov tokens is very important that the backend server is synchronizing automatically the system clock over the network with an authoritative time source. In Linux this is usually done with a NTP server.


## Issues

If you find any issue while following our instructions then just report it [here](https://github.com/approov/quickstart-python-token-check/issues), with the steps to reproduce it, and we will sort it out and/or guide you to the correct path.


## Useful Links

If you wish to explore the Approov solution in more depth, then why not try one of the following links as a jumping off point:

* [Approov Free Trial](https://approov.io/signup)(no credit card needed)
* [Approov Get Started](https://approov.io/product/demo)
* [Approov QuickStarts](https://approov.io/docs/latest/approov-integration-examples/)
* [Approov Docs](https://approov.io/docs)
* [Approov Blog](https://approov.io/blog/)
* [Approov Resources](https://approov.io/resource/)
* [Approov Customer Stories](https://approov.io/customer)
* [Approov Support](https://approov.io/contact)
* [About Us](https://approov.io/company)
* [Contact Us](https://approov.io/contact)
