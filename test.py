#! /usr/bin/env python

import requests
import logger
from flask import Flask, request, Response
import os
import jwt
import datetime
import time
import hashlib
import json
import base64

#from zeep import Client
#from zeep import helpers
#from zeep.transports import Transport
#from zeep.plugins import HistoryPlugin
"""
a = "-----BEGIN CERTIFICATE-----\nMIIFzjCCBLagAwIBAgIKYQ8q/gAAAAAABDANBgkqhkiG9w0BAQUFADA9MQswCQYD\nVQQGEwJOTzERMA8GA1UEChMIU3RhdG5ldHQxGzAZBgNVBAMTElN0YXRuZXR0IFJv\nb3QgQ0EgMjAeFw0xMTA0MTMxMDAzNTdaFw0yMTA0MTMxMDEzNTdaMEAxCzAJBgNV\nBAYTAk5PMREwDwYDVQQKEwhTdGF0bmV0dDEeMBwGA1UEAxMVU3RhdG5ldHQgSXNz\ndWluZyBDQSA0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz9GZiomy\nGvoX5Szz/01frPzL2kRrgjthhiDPwsiSaNOGf5GjyHyFFDbQLG4uCf41kmcVgxHe\ntu0bIplPM7PDqo86PvHTaQxzHNoj30okjDo32ssta9BO4TTf5vCCWC6752s4DOsy\nsWbxy2XhY37fg7RHdHAPdKQHlOQDUcCmAYAHCy0DqniK+xD+91JfK1hHUiYjkGag\nC1M+1XVcV5A8ophqGDgh2df7zQP3AF/L8VrMTrSnNtdJnGGUyFEEiwMjQlx3lFlP\n1SZ9bOpmC+VWqg2FeLNLb5HnNGsILHTSuAwfr3FGORwUIv+/jXVvE+uW7/JCg2yD\ne58NyhV0JkT9XwIDAQABo4ICyzCCAscwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4E\nFgQUGs1xsPgG/g/8zc22aIxaZRcCUqIwCwYDVR0PBAQDAgGGMBAGCSsGAQQBgjcV\nAQQDAgEAMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMB8GA1UdIwQYMBaAFDgD\nsBcbG/ZGdWyfC+wJAxzSUhhOMIIBFwYDVR0fBIIBDjCCAQowggEGoIIBAqCB/4aB\nwmxkYXA6Ly8vQ049U3RhdG5ldHQlMjBSb290JTIwQ0ElMjAyLENOPW9zbHJvb3Rj\nYTIsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2Vz\nLENOPUNvbmZpZ3VyYXRpb24sREM9U3RhdG5ldHQsREM9bm8/Y2VydGlmaWNhdGVS\nZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlvblBv\naW50hjhodHRwOi8vcGtpLnN0YXRuZXR0Lm5vL0NlcnQvU3RhdG5ldHQlMjBSb290\nJTIwQ0ElMjAyLmNybDCCAR0GCCsGAQUFBwEBBIIBDzCCAQswgbcGCCsGAQUFBzAC\nhoGqbGRhcDovLy9DTj1TdGF0bmV0dCUyMFJvb3QlMjBDQSUyMDIsQ049QUlBLENO\nPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3Vy\nYXRpb24sREM9U3RhdG5ldHQsREM9bm8/Y0FDZXJ0aWZpY2F0ZT9iYXNlP29iamVj\ndENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwTwYIKwYBBQUHMAKGQ2h0dHA6\nLy9wa2kuc3RhdG5ldHQubm8vQ2VydC9vc2xyb290Y2EyX1N0YXRuZXR0JTIwUm9v\ndCUyMENBJTIwMi5jcnQwDQYJKoZIhvcNAQEFBQADggEBADU71KSfVr4B/xdQ7XTu\n922Nnm8JThQbdyd+xXV85R8VF6GihUTdQAY8G8ysZeE4q92q78VH0ntAvy4BbIsx\neFqz+zndwOjQPPm2npVcE8nqmZPEusMooZcIGbCR8Sn4AbtJ8bQ2AesB7f0Ejb96\nqtvKwAzMk6GUh2HCDY2nF7A3qc/KB8UQTRmJqnUWqg/D4I9DwokgtEWjVSbol6F2\nG2p1te0d9113MsJU7gmitQkBjS/RnyPHy+nYiIaA06xVzLFgA6V/tJAknyvKyPKb\nAP0Ga3YU4UOEOodmdLxtMFB3qht7jIE8xtqcdrDVLKzy72xOxkCEDtFDOsk7vASn\n08I=\n-----END CERTIFICATE-----"

cert1 = load_certificate(FILETYPE_PEM, a)
open("StatnettIssuingC4_sha1.pem", 'wb').write(bytes(a, 'ascii'))
os.system("update-ca-certificates")

#os.system("mv StatnettIssuingC4_sha1.pem /etc/ssl/certs/")
ss"""


b = datetime.datetime.now() + datetime.timedelta(seconds=1000)
print(b)
print(b.strftime('%s'))

a = "xk3DCW2bUAnPhutkzsyK"

#58140106b2bbadda06edc377d6f6f779f0e4e709db344a8310fcca31df9ee8b7
#e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

expiry=30
sha256_hash = hashlib.sha256()
hash_digest = sha256_hash.hexdigest()
#print(hash_digest)
hash_digest = "58140106b2bbadda06edc377d6f6f779f0e4e709db344a8310fcca31df9ee8b7"
time = datetime.datetime.now() + datetime.timedelta(seconds=expiry*1000)
payload={"iss": "Bluegarden", "exp":time.strftime('%f'), "sha256":hash_digest}
#payload={"iss": "Bluegarden", "exp":datetime.datetime.now() + datetime.timedelta(seconds=expiry*1000), "digest":hash_digest, "iat":1623051600}
encoded_jwt = jwt.encode(payload, a, algorithm="HS256", headers={"digestAlgorithm":"SHA256"})
print(encoded_jwt)

ss

#eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJCbHVlZ2FyZGVuIiwiZXhwIjoxNjIzMzY3OTg4LCJkaWdlc3QiOiJlM2IwYzQ0Mjk4ZmMxYzE0OWFmYmY0Yzg5OTZmYjkyNDI3YWU0MWU0NjQ5YjkzNGNhNDk1OTkxYjc4NTJiODU1In0.QwYYzrPTpPOYcIG2Dkss30h6_Xw6_OGUVhVLVrS10bM




def get_token():
    """
    expiry=30
    payload={"iss": "Bluegarden", "exp":datetime.datetime.now() + datetime.timedelta(seconds=expiry*1000)}
    encoded_jwt = jwt.encode(payload, os.environ.get("SIGNING_KEY"), algorithm="HS256")
    sha256_hash = hashlib.sha256()
    sha256_hash.update(encoded_jwt)
    hash_digest = sha256_hash.hexdigest()
    return hash_digest
    """

    expiry=30
    auth = os.environ.get('authentication', "")
    sha256_hash = hashlib.sha256()
    hash_digest = sha256_hash.hexdigest()
    payload={"iss": "Bluegarden", "exp":datetime.datetime.now() + datetime.timedelta(seconds=expiry*1000), "digest":hash_digest}#, "iat": 1623051600}
    encoded_jwt = jwt.encode(payload, os.environ.get("SIGNING_KEY"), algorithm="HS256", headers= {"digestAlgorithm": "SHA256"})
    #encoded_jwt = jwt.encode(payload, a, algorithm="HS256", headers= {"digestAlgorithm": "SHA256"})
    return encoded_jwt.decode("UTF-8")

"""
#f = open("/usr/local/share/ca-certificates/StatnettIssuingC4_sha1.pem", "w")
with open("/usr/local/share/ca-certificates/StatnettIssuingC4_sha1.pem", "wb") as f:
    f.write(cert1)
ss
b = open("/usr/local/share/ca-certificates/StatnettIssuingC4_sha1.pem", "r")
print(f.read().get_notBefore())
ss
"""
rootlogger=logger.Logger()

time.sleep(20)

token = get_token()
rootlogger.info(token)
r = requests.get(os.environ.get("url"), headers={"Authorization": "Bearer {}".format(token)}, verify="/etc/ssl/certs/ca-certificates.crt")
if r.status_code == 200:
    rootlogger.info("JWT new wsdl url OK")
    rootlogger.info(r.content)

r = requests.get(os.environ.get("url2"), headers={"Authorization": "Bearer {}".format(token)}, verify="/etc/ssl/certs/ca-certificates.crt")
if r.status_code == 200:
    rootlogger.info("JWT old wsdl url OK")
    rootlogger.info(r.content)


body = """<?xml version='1.0' encoding='utf-8'?>
    <soap-env:Envelope xmlns:soap-env="http://schemas.xmlsoap.org/soap/envelope/">
    <soap-env:Header>
        <ns0:BSBHeader xmlns:ns0="http://bluemsg.bluegarden.no/object/v3">
            <SourceCompany>405</SourceCompany>
            <SourceEmployer>4050010</SourceEmployer>
            <SourceSystem>STATNETT</SourceSystem>
            <SourceUser>statnett</SourceUser>
            <MessageId>abcdef0123450123456789abcdef0123456789</MessageId>
        </ns0:BSBHeader>
    </soap-env:Header>
    <soap-env:Body>
        <ns0:GetAllAlertsRequest xmlns:ns0="http://getallalerts.bluegarden.no/service/v3">
            <ns0:employerID>4050010</ns0:employerID>
        </ns0:GetAllAlertsRequest>
    </soap-env:Body>
</soap-env:Envelope>"""

"""
r = requests.post(os.environ.get("url-endpoint"), headers={"Authorization": "Bearer {}".format(get_token()), "Content-Type": "text/xml; charset=utf-8", "apikey":"BTNUdpRS9sBxk33ec3Ct"}, verify="/etc/ssl/certs/ca-certificates.crt", data=body)
rootlogger.info(r.content)

r = requests.post(os.environ.get("url-endpoint"), headers={"Authorization": "Bearer {}".format(get_token()), "Content-Type": "application/xml"}, verify="/etc/ssl/certs/ca-certificates.crt")
rootlogger.info(r.content)

r = requests.post(os.environ.get("url-endpoint"), headers={"Authorization": "Bearer {}".format(get_token())}, verify="/etc/ssl/certs/ca-certificates.crt")
rootlogger.info(r.content)


ss
#rootlogger.info(r)
#url = "https://api-test.statnett.no/services/hrls/auth-proxy/alerts/get-all?apikey=BTNUdpRS9sBxk33ex3Ct"

app = Flask(__name__)


s = requests.Session()
s.verify="/etc/ssl/certs/ca-certificates.crt"
s.headers={"Authorization": "Bearer {}".format(get_token())}
transport=Transport(session=s)
#url = "https://api-test.statnett.no/services/hrls/auth-proxy/alerts?wsdl&apikey=BTNUdpRS9sBxk33ex3Ct"
client = Client(wsdl=os.environ.get("url"), transport=transport)



@app.route('/', methods=['POST', 'GET'])
def push():

    entities = request.get_json()
    return_entities = []
    if not isinstance(entities, list):
        entities = [entities]

    for entity in entities:
        if os.environ.get('transit_decode', 'false').lower() == "true":
            rootlogger.info("transit_decode is set to True.")
            entity = typetransformer.transit_decode(entity)

        rootlogger.info("Finished creating request: " + str(entity))

        response = do_soap(entity,client)
        serialized_response=helpers.serialize_object(response)
        return_entities.extend(serialized_response)
        rootlogger.info(serialized_responsee)
        rootlogger.info("Prosessed " + str(len(serialized_response)) + " Entities")

    rootlogger.info("ehm?")
    return Response(response=json.dumps(return_entities, default=typetransformer.json_serial), mimetype='application/json')




def do_soap(entity, client):
    headers = entity['_soapheaders']
    filtered_entity = {i:entity[i] for i in entity if not i.startswith('_') }
    filtered_entity['_soapheaders']=headers
    #service = client.create_service("{http://getallalerts.bluegarden.no/service/v3/wsdl}GetAllAlertsServiceServiceSoapBinding", "https://api-test.statnett.no/services/hrls/auth-proxy/alerts/get-all?apikey=BTNUdpRS9sBxk33ex3Ct")
    #service.submit('something')
    #with client.settings(raw_response=True):


    try:
        rootlogger.info(client.create_message(client.service, 'GetAllAlerts', **filtered_entity))
    except Exception as e:
        print("Error1 = ",e)


    try:
        response = client.service.GetAllAlerts(**filtered_entity, _soapheaders={"Authorization": "Bearer {}".format(get_token())})
        rootlogger.info("success")
    except Exception as e:
        print("Error4 = ",e)

    rootlogger.info("2")
    #rootlogger.info(type(response))
    #rootlogger.info("3")
    try:
        rootlogger.info(response.content)
    except Exception as e:
        print("Error5 = ",e)
    rootlogger.info("4")
    rootlogger.info(response.text)
    rootlogger.info("4")

    return response

#requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += os.environ.get('cipher', ':ECDHE-RSA-AES128-SHA')
#timeout=int(os.environ.get('timeout', '30'))

#
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=os.environ.get('port',5001))
