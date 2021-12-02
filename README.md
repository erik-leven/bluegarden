# SOAP-source built with Zeep

A small microservice to post data to a SOAP endpoint and receive result in JSON.
All entities must have a "_soapheaders" attribute.

[![Build Status](https://travis-ci.org/sesam-community/soap-zeep-source.svg?branch=master)](https://travis-ci.org/sesam-community/soap-zeep-source)

##### Example entity
```
{
  "_ts": 1486128503194780,
  "_previous": null,
  "_hash": "50d93095f6fb68e7517ea89e62c60af8",
  "_id": "29932",
  "_deleted": false,
  "_updated": 8,
  "_soapheaders": {
    "headerName": {
      [...]
    }
  },
  "RestOfSOAP": {
    [...]
  }
}
```
##### Example returned result:
```
[
    {
        "Id": 1,
        "foo": "bar"
    },
    {
        "Id": 2,
        "foo": "baz"
    }
]
```
##### Example configuration:

```
{
  "_id": "soap-service",
  "type": "system:microservice",
  "docker": {
    "environment": {
      "method": "fetchDataFromSOAPSource",
      "url": "http://localhost:8088/SomeSOAPSource?WSDL",
      # optional values below
      "authentication": "basic",
      "username": "theUsername",
      "password": "thePassword",
      "timeout": 30,
      "cipher": ":ECDHE-RSA-AES128-SHA",
      "transit_decode": "false"
    },
    "image": "sesamcommunity/soap-zeep-source:latest",
    "port": 5001
  }
}
```


