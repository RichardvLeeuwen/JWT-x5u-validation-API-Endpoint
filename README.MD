# JWT with x5u validation API endpoint

This repository provides an API endpoint that returns the validity of a JWT with x5u header that points to a PEM-encoded X.509 certificate URL. The JWT is signed using the RS256 algorithm and the signature is validated with the aforementioned X.509 certificate.

## Requirements
The project uses Python 3.12.1 and the libraries Flask, pytest, cryptography, requests and PyJWT. To easily install these libraries, please run 'pip install -r requirements.txt' in the root directory.

## Set-up
The API endpoint is run with the command 'flask --app flaskServer run' from the root directory with the default address http://127.0.0.1:5000.

For testing purposes, there is a private key named 'enablebankprivate.key' in the root directory and there is a directory called certServer containing the associated self-signed X.509 certificate named 'enablebankingcert.pem'. To run the certificate server, please use the command 'python -m http.server 9000' inside  the certServer directory.

Further, by running the command 'pytest' in the root directory, a list of different tests will be run using the test certificate server to test the API endpoint for various possible circumstances. These tests can be found in the test_jwtIntegration.py file.

## The API endpoint
The API endpoint is accessible at http://127.0.0.1:5000 through a GET request. This GET request should contain an Authorization header with a JWT bearer token. This JWT expects in its header a x5u field that links to a PEM-encoded x.509 certificate containing the public key to decode the JWT. Further, it is expected that the JWT is signed with the RS256 algorithm and contains the fields iat, exp and issuer. For the issuer field, the API endpoint expects the value 'enableBankingJobApplication'. Please see RFC 7519 (JSON Web Token) and RFC 7517 (JSON Web Key) for additional information on these fields and expected behaviour. 

The API endpoint will respond if the token is valid or not in a json with the field {'valid':true/false}. In the event the token is invalid, there is an additional field called 'issue' that details the reason.

Examples responses could be the following:
1. Valid token:
{'valid':true}
2. Invalid token, expired exp value:
{{'valid':false,'issue':"Signature has expired"}}
3. Invalid token, invalid issuer:
{{'valid':false,'issue':"Invalid issuer"}}

## Security concerns
For development and testing purposes, a self-signed X.509 certificate is used. However, this would be a security issue in a public setting as a malicious attacker could modify the JWT and substitute the signature with their own signature linking the x5u field to their own, personal certificate. To prevent this from happening, it is recommended to have the certificate signed by a Certificate Authority (CA) and checked for its validity before usage.
