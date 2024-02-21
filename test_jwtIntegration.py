import requests
import datetime
import jwtHelper

PRIVATEKEYLOCATION = "enablebankprivate.key"

VALIDISSUER = "enableBankingJobApplication"
INVALIDISSUER = "evilCorp.com"

VALIDIAT = int(datetime.datetime.now().timestamp())
INVALIDIAT = "badType"

VALIDEXP = VALIDIAT + 86400 #24 hours
INVALIDEXP = 0

VALIDX5ULINK = "http://127.0.0.1:9000/enablebankingcert.pem"
INVALIDX5ULINK = "wrongwebsite.com"

def test_validJwt():
    jwtToken = jwtHelper.encodeJWTUsingX5u(VALIDISSUER, VALIDIAT, VALIDEXP,VALIDX5ULINK,PRIVATEKEYLOCATION)
    returnedData = requests.get("http://127.0.0.1:5000",headers={"Authorization" : f"Bearer {jwtToken}"})
    assert returnedData.json()['valid'] == True

def test_invalidIat():
    jwtToken = jwtHelper.encodeJWTUsingX5u(VALIDISSUER, INVALIDIAT, VALIDEXP,VALIDX5ULINK,PRIVATEKEYLOCATION)
    returnedData = requests.get("http://127.0.0.1:5000",headers={"Authorization" : f"Bearer {jwtToken}"})
    assert returnedData.json()['valid'] == False
    assert returnedData.json()['issue'] == "Issued At claim (iat) must be an integer."

def test_invalidExp():
    jwtToken = jwtHelper.encodeJWTUsingX5u(VALIDISSUER, VALIDIAT, INVALIDEXP,VALIDX5ULINK,PRIVATEKEYLOCATION)
    returnedData = requests.get("http://127.0.0.1:5000",headers={"Authorization" : f"Bearer {jwtToken}"})
    assert returnedData.json()['valid'] == False
    assert returnedData.json()['issue'] == "Signature has expired"


def test_invalidIssuer():
    jwtToken = jwtHelper.encodeJWTUsingX5u(INVALIDISSUER, VALIDIAT, VALIDEXP,VALIDX5ULINK,PRIVATEKEYLOCATION)
    returnedData = requests.get("http://127.0.0.1:5000",headers={"Authorization" : f"Bearer {jwtToken}"})
    assert returnedData.json()['valid'] == False
    assert returnedData.json()['issue'] == "Invalid issuer"

def test_invalidX5U():
    jwtToken = jwtHelper.encodeJWTUsingX5u(VALIDISSUER, VALIDIAT, VALIDEXP,INVALIDX5ULINK,PRIVATEKEYLOCATION)
    returnedData = requests.get("http://127.0.0.1:5000",headers={"Authorization" : f"Bearer {jwtToken}"})
    assert returnedData.json()['valid'] == False
    assert "Invalid URL" in returnedData.json()['issue']