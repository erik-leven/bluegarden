#! /usr/bin/env python

import requests
import logger
from flask import Flask, request, Response
import os
import datetime
import time
import hashlib
import json
import base64
from jose import jwt as jose_jwt
import xmltodict
from jose import jwt
import xml.etree.ElementTree as ET

rootlogger=logger.Logger()
app = Flask(__name__)

issuer = os.environ.get("issuer")
key = os.environ.get("signing_key")
algorithm = os.environ.get("algorithm")
headers = json.loads(os.environ.get("headers"))
timedelta = int(os.environ.get("timedelta"))

alerts_base_xml = os.environ.get("alerts_base_xml")
userforms_base_xml = os.environ.get("userforms_base_xml")
cert_path = os.environ.get("cert_path")
api_key = os.environ.get("apikey")

def store_cert(cert_name, cert):
    cert_name += ".pem"
    cert_file = open(os.path.join(cert_path, cert_name), "w")
    try:
        cert_file.write(cert + "\n")
    except PermissionError:
        rootlogger.info("No permissions")
    cert_file.close
    cert_file = open(os.path.join(cert_path, cert_name), "r")
    cert_file.close

def create_body(my_dict, person_status,ansettelsesforhold_status, arbeidsforhold_status):
    ET.SubElement(my_dict, "CreateMedarbeiderEntityRequest")
    create_CreateMedarbeiderEntityRequest(my_dict.find("CreateMedarbeiderEntityRequest"), person_status,ansettelsesforhold_status, arbeidsforhold_status)

def create_CreateMedarbeiderEntityRequest(my_dict, person_status,ansettelsesforhold_status, arbeidsforhold_status):
    ET.SubElement(my_dict, "Medarbeider")
    my_dict.set("xmlns","http://bluegarden.no/esb/medarbeider/adapter/service/v1_1")
    create_Medarbeider(my_dict.find("Medarbeider"), person_status,ansettelsesforhold_status, arbeidsforhold_status)

def create_Arbeidsforhold(my_dict):
    ET.SubElement(my_dict, "ArbeidsforholdID")
    ET.SubElement(my_dict, "AnsattforholdsKode")
    ET.SubElement(my_dict, "Arbeidsforholdnummer")
    ET.SubElement(my_dict, "Startdato")
    ET.SubElement(my_dict, "Stoppdato")
    ET.SubElement(my_dict, "NyStoppdato")
    ET.SubElement(my_dict, "Avlonningstype")
    ET.SubElement(my_dict, "Arbeidsforholdstype")
    ET.SubElement(my_dict, "OrganisasjonsenhetID")
    ET.SubElement(my_dict, "Stilling")
    ET.SubElement(my_dict, "Utbetalingsprosent")
    ET.SubElement(my_dict, "Lonnskode")
    ET.SubElement(my_dict, "Feriekode")
    ET.SubElement(my_dict, "Regulativkode")

def create_Ansettelsesforhold(my_dict, arbeidsforhold_status):
    ET.SubElement(my_dict, "Arbeidsgivernummer")
    ET.SubElement(my_dict, "Ansattnummer")
    ET.SubElement(my_dict, "Skattetype")
    if arbeidsforhold_status != "None":
        ET.SubElement(my_dict, "Arbeidsforhold", status=arbeidsforhold_status)
    else:
        ET.SubElement(my_dict, "Arbeidsforhold")
    create_Arbeidsforhold(my_dict.find("Arbeidsforhold"))


def create_Person(my_dict, person_status):
    ET.SubElement(my_dict, "Etternavn")
    ET.SubElement(my_dict, "Fornavn")
    if person_status == "Aktiv":
        ET.SubElement(my_dict, "Fodselsnummer")
        ET.SubElement(my_dict.find("Fodselsnummer"), "IdValue")
    ET.SubElement(my_dict, "Sluttoppgjorskode")
    ET.SubElement(my_dict, "Sluttarsakskode")
    ET.SubElement(my_dict, "HentSkattekort")
    ET.SubElement(my_dict, "Frikort")
    ET.SubElement(my_dict, "Pensjonisttabell")
    ET.SubElement(my_dict, "Biarbeidsgiver")
    ET.SubElement(my_dict, "Startdato")
    ET.SubElement(my_dict, "Mobiltelefon")
    ET.SubElement(my_dict, "PrivatMobil")
    ET.SubElement(my_dict, "Arbeidsforholdnummer")
    ET.SubElement(my_dict, "Stoppdato")
    ET.SubElement(my_dict, "Signatur")

def create_Kontaktinformasjon(my_dict):
    ET.SubElement(my_dict, "E-post")
    ET.SubElement(my_dict, "Adresse")
    ET.SubElement(my_dict.find("Adresse"), "AdresseLinje1")
    my_dict.find("Adresse").find("AdresseLinje1").set("xmlns","http://common.bluegarden.no/object/v1_5")
    ET.SubElement(my_dict.find("Adresse"), "Postnummer")
    my_dict.find("Adresse").find("Postnummer").set("xmlns","http://common.bluegarden.no/object/v1_5")
    ET.SubElement(my_dict.find("Adresse"), "Poststed")
    my_dict.find("Adresse").find("Poststed").set("xmlns","http://common.bluegarden.no/object/v1_5")
    ET.SubElement(my_dict.find("Adresse"), "Land")
    my_dict.find("Adresse").find("Land").set("xmlns","http://common.bluegarden.no/object/v1_5")
    ET.SubElement(my_dict, "Telefonnummer")

def create_header(my_dict):
    ET.SubElement(my_dict, "BlueMsgHeader")
    create_BlueMsgHeader(my_dict.find("BlueMsgHeader"))


def create_BlueMsgHeader(my_dict):
    my_dict.tag = "h:BlueMsgHeader"
    my_dict.set("xmlns", "http://bluemsg.bluegarden.no/object/v1")
    my_dict.set("xmlns:xsd", "http://www.w3.org/2001/XMLSchema")
    my_dict.set("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
    my_dict.set("xmlns:h", "http://bluemsg.bluegarden.no/object/v1")
    ET.SubElement(my_dict, "MessageId")
    ET.SubElement(my_dict, "MessageType")
    ET.SubElement(my_dict, "Action")
    ET.SubElement(my_dict, "SourceSystemTimestamp")
    ET.SubElement(my_dict, "SourceCompany")
    ET.SubElement(my_dict, "SourceEmployer")
    ET.SubElement(my_dict, "SourceSystem")
    ET.SubElement(my_dict, "SourceUser")
    ET.SubElement(my_dict, "SourceRef")
    for SubElement in my_dict:
        SubElement.set("xmlns", "")


def create_Medarbeider(my_dict, person_status, ansettelsesforhold_status, arbeidsforhold_status):
    my_dict.set("xmlns","http://bluegarden.no/esb/medarbeider/adapter/object/v1_1")
    if person_status != "None":
        ET.SubElement(my_dict, "Person", status=person_status)
    else:
        ET.SubElement(my_dict, "Person")
    create_Person(my_dict.find("Person"), person_status)
    ET.SubElement(my_dict, "Kontaktinformasjon", kontaktinformasjonType="Bosted")
    create_Kontaktinformasjon(my_dict.find("Kontaktinformasjon"))
    if ansettelsesforhold_status != "None":
        ET.SubElement(my_dict, "Ansettelsesforhold", status=ansettelsesforhold_status)
    else:
        ET.SubElement(my_dict, "Ansettelsesforhold")
    create_Ansettelsesforhold(my_dict.find("Ansettelsesforhold"), arbeidsforhold_status)


def create_medarbeider_xml(my_dict, person_status,ansettelsesforhold_status, arbeidsforhold_status, origin=None, data = None):
    if my_dict.tag == "{http://schemas.xmlsoap.org/soap/envelope/}Header":
        create_header(my_dict)

    if my_dict.tag == "{http://schemas.xmlsoap.org/soap/envelope/}Body":
        my_dict.set("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
        my_dict.set("xmlns:xsd", "http://www.w3.org/2001/XMLSchema")
        create_body(my_dict, person_status,ansettelsesforhold_status, arbeidsforhold_status)

    for key in my_dict:
        if len([el for el in key]) > 0: 
            create_medarbeider_xml(key, origin, person_status, ansettelsesforhold_status, arbeidsforhold_status)



def iterate_dict(my_dict, entity,origin=None):
    if not origin:
        origin = []
        try:
            origin.append(my_dict.tag.split("}")[1])
        except IndexError:
            origin.append(my_dict.tag.split(":")[1])
    for key in [key for key in my_dict]:
        data = None
        if len([el for el in key]) > 0:
            if ":" in key.tag:
                origin.append(key.tag.split(":")[1])
            else:
                origin.append(key.tag)
            iterate_dict(key, entity, origin)
        else:
            for orig in origin:
                try:
                    if not data:
                        data = entity[orig]
                    else:
                        data = data[orig]
                    
                except KeyError:
                    pass

            try:
                key.text = str(data[key.tag].strip("$"))
            except TypeError:
                key.text = str(data[key.tag])
            except AttributeError:
                key.text = str(data[key.tag])
            except KeyError:
                try:
                    my_dict.remove(key),
                except ValueError:
                    pass

    del origin[-1]

try:
    remove_namespaces = json.loads(os.environ.get("remove_namespaces"))
    namespaces = {}
    for namespace in remove_namespaces:
        namespaces[namespace]=None
except TypeError:
    namespaces = None

def remove_empty_property(xml):
    for child in xml:
        if len([grand_child for grand_child in child]) > 0:
            remove_empty_property(child)
        elif not child.text:
            xml.remove(child) 
        else:
            pass
def get_token(data):
    time = (datetime.datetime.now() + datetime.timedelta(seconds=timedelta)).timestamp()
    payload={"sha256":hashlib.sha256(data.encode()).hexdigest(), "iss": issuer,"digest":hashlib.sha256(data.encode()).hexdigest(), "exp":time}
    token = jose_jwt.encode(payload, key, algorithm=algorithm, headers=headers)
    return token

def find_faultstring(xml):
    msg = None
    for child in xml.find("{http://schemas.xmlsoap.org/soap/envelope/}Body"):
        for child2 in child:
            if child2.tag == "faultstring":
                msg = child2.text
    return msg

def create_xml(data, root, path):
    for key in data.keys():
        for elem in root.iter():
            if elem.tag == "{http://getall" + path + ".bluegarden.no/service/v3}" + key:
                elem.text = data[key]
            elif elem.tag == key:
                elem.text = str(data[key])
    return ET.tostring(root).decode()

def create_certificates():
    try:
        for key, val in json.loads(os.environ.get("certificates")).items():
            store_cert(key, val)
        rootlogger.info("Certificates added")
    except KeyError:
        rootlogger.info("No certificates located")
    os.system("update-ca-certificates")

@app.route("/<path>", methods=["POST", "GET"])
def push(path):
    xml_path = path + "_base_xml"
    root = ET.fromstring(os.environ.get(xml_path))
    url = os.environ.get("url") + "/" + path + "?apikey=" + api_key
    data_location = json.loads(os.environ.get(path + "_data_location"))
    try:
        for key, val in json.loads(os.environ.get("certificates")).items():
            store_cert(key, val)
            rootlogger.info("Added certificate %s" % key)
    except KeyError:
        rootlogger.info("No certificates located")
    os.system("update-ca-certificates")
    entities = request.get_json()
    return_entities = []
    if not isinstance(entities, list):
        entities = [entities]
    for i, entity in enumerate(entities):
        entity = create_xml(entity, root, path)
        response = requests.post(url, verify="/etc/ssl/certs/ca-certificates.crt", data=entity, headers={"Authorization": "Bearer {}".format(get_token(entity)), "Content-Type": "application/soap+xml"})
        r = json.loads(json.dumps(xmltodict.parse(response.content, process_namespaces=True, namespaces=namespaces)))
        if data_location:
            for key in data_location:
                r = r[key]
        return_entities.extend(r)
        rootlogger.info("Proccessed %i entities" % len(r))
    return Response(json.dumps(return_entities), mimetype="application/json")

@app.route("/medarbeider/<person_status>/<ansettelsesforhold_status>/<arbeidsforhold_status>", methods=["POST", "GET"])
def post(person_status, ansettelsesforhold_status, arbeidsforhold_status):
    xml_path = os.environ.get("medarbeider_base_xml")
    entities = request.get_json()
    create_certificates()
    if not isinstance(entities, list):
        entities = [entities]
    url = os.environ.get("url") + "/medarbeider?apikey=" + api_key
    for i, entity in enumerate(entities):        
        root = ET.fromstring(xml_path)
        ET.register_namespace("s", 'http://schemas.xmlsoap.org/soap/envelope/')
        for root_element in root:
            create_medarbeider_xml(root_element, person_status, ansettelsesforhold_status, arbeidsforhold_status)
            iterate_dict(root_element, entity)
        remove_empty_property(root)
        try:
            response = requests.post(url, verify="/etc/ssl/certs/ca-certificates.crt", data=ET.tostring(root).decode(), headers={"Authorization": "Bearer {}".format(get_token(ET.tostring(root).decode())), "Content-Type": "application/soap+xml", "soapaction":'"createMedarbeiderEntity"'})
        except Exception as e:
            rootlogger.info("Error: ",e)
        response_xml = ET.fromstring(response.text)
        error = find_faultstring(response_xml)

        if str(entity["Medarbeider"]["Ansettelsesforhold"]["Ansattnummer"]) == "0000":
            log_msg = str(entity["Medarbeider"]["Person"]["Fornavn"]) + " " + str(entity["Medarbeider"]["Person"]["Etternavn"]) + ": "
        else:
            log_msg = str(entity["Medarbeider"]["Ansettelsesforhold"]["Ansattnummer"]) + ": "
        if error:
            rootlogger.info("----------------------------------------------------------------------------------------------------")
            rootlogger.error("The following error was reported for employee " + log_msg + str(error))
            rootlogger.info("The created xml was: " + str(ET.tostring(root).decode()))
            rootlogger.info("----------------------------------------------------------------------------------------------------")
            exit()
        else:            
            rootlogger.info("----------------------------------------------------------------------------------------------------")
            rootlogger.info("Request sent successfully for user: " + log_msg)
            rootlogger.info("----------------------------------------------------------------------------------------------------")

    return "Post successful"

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=os.environ.get("port",5001))





