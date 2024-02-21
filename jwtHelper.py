import jwt
import requests
from cryptography.x509 import load_pem_x509_certificate

def returnX5UValue(token):
    headerData = jwt.get_unverified_header(token)
    return headerData['x5u']

def returnUnverifiedJWTPayload(token):
    return jwt.decode(token, options={"verify_signature": False})

def decodeJWTUsingX5U(x5uLink, token, jwtIssuer):
    data = requests.get(x5uLink)
    certData = data.text
    pemCertObject = load_pem_x509_certificate(certData.encode('utf-8'))
    publicKey = pemCertObject.public_key()
    return jwt.decode(token, key=publicKey, algorithms=['RS256'], issuer=jwtIssuer)

def encodeJWTUsingX5u(jwtIssuer, iat, expTime, x5uLink, privateKeyLocation):
    jwtPayload = {"iss":jwtIssuer,"iat":iat,"exp":expTime}
    privateKey= open(privateKeyLocation,'r').read()
    return jwt.encode(payload=jwtPayload, key=privateKey,algorithm="RS256", headers={'x5u':x5uLink})