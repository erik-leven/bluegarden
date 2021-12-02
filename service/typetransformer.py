import datetime

def transit_decode(part):
    if not isinstance(part, list):
        part = [part]
    for entity in part:
        for key, val in entity.items():
            if isinstance(val, dict) or isinstance(val,list):
                transit_decode(val)
            elif isinstance(val, str) and val.startswith("$"):
                entity[key]=transit_decode_datetime(val)
    return entity

def transit_decode_datetime(val):
    if len(val) == 11:
        return datetime.datetime.strptime(val, '$%Y-%m-%d').date()
    else:
        return datetime.datetime.strptime(val, '$%Y-%m-%dT%H:%M:%S.%fZ')

def json_serial(o):
    ''''Serializing datetime to to json'''''
    if type(o) is datetime.date or type(o) is datetime.datetime:
        return o.isoformat()