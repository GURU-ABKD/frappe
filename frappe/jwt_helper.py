import json, datetime, jwt, frappe, bcrypt
from frappe import _
from hashlib import blake2b
from hmac import compare_digest


jwt_conf = {
    "secret_key": "TRINITY2022",
    "expiration_in_days": 1,
    "algorithm": "HS256"
}


def validate_jwt_token(token):
    if not token:
        frappe.throw(_("Missing Token"))

    try:
        data = jwt_decoder(token)
        user = frappe.get_doc("User", data['user'])
        if user:
            if verify_hashed(user.api_key, data['key']):
                return {"key": user.api_key, "secret": user.get_password("api_secret"), "user": data['user']}
            else:
                frappe(_("Password did not matched"))

    except jwt.ExpiredSignatureError:
        frappe.throw(_("Token Expired"))
        return jsonify({"valid": False})
    except jwt.InvalidTokenError:
        frappe.throw(_("Invalid Token"))
        return jsonify({"valid": False})


def jwt_decoder(token):
    decoded = jwt.decode(token, jwt_conf['secret_key'], algorithm=jwt_conf['algorithm'])
    return decoded


def jsonify(data):
    """
        Serialize data to JSON
    """
    return json.dumps(data, default=default)


def default(o):
    """
        Usage in jsonify to deserialize datetime objects.
    """
    if isinstance(o, (datetime.date, datetime.datetime)):
        # TODO: dateformat to be human readable
        return o.isoformat()


def jwt_encoder(user):
    try:
        user = frappe.get_value("User", {"name": user}, ['api_key', 'name'], as_dict=1)
        if user.api_key:
            now = datetime.datetime.now()
            payload = {
                "user": user.name,
                "exp": now + datetime.timedelta(days=int(1)),
                "key": hashed_token(user.api_key)
            }
            token = jwt.encode(payload, jwt_conf['secret_key'], algorithm=jwt_conf['algorithm'])
            return token.decode('utf-8')
        else:
            frappe.throw(_("No api key found. Please contact Administrator"))
    except Exception as e:
        frappe.log_error(frappe.get_traceback(), "Login error")
        frappe.throw(_(str(e)))
        

def hashed_token(cookie):
    h = blake2b(digest_size=16, key=b'TRINITY2022')
    h.update(bytes(cookie, 'utf-8'))
    hashed = h.hexdigest().encode('utf-8')
    return hashed.decode("utf-8")


def verify_hashed(cookie, key):
    cur_key = hashed_token(cookie)
    if compare_digest(cur_key, key):
        return True
    else:
        frappe.throw(_("Invalid Token"))


