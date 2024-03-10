from flask import Flask, jsonify, request
import jwtHelper

app = Flask(__name__)

@app.route('/', methods=['GET'])
def getJWTValidity():
    try:
        requestAuthorizationHeader = request.headers['Authorization']
        jwtToken = requestAuthorizationHeader.split()[1]
        x5uValue = jwtHelper.returnX5UValue(token=jwtToken)
        payload = jwtHelper.decodeJWTUsingX5U(x5uLink=x5uValue, token=jwtToken, jwtIssuer="Richard") 
        print(payload)
        return jsonify({"valid":True}), 200
    except Exception as e:
        print(str(e))
        return jsonify({"valid":False, "issue": str(e)}), 401
