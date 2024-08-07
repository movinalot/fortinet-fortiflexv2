"""
    FortiFlex
    John McDonough (@movinalot)
    Fortinet
"""

# pylint: disable=too-many-branches

import json
import logging
import os
import re
import requests
import azure.functions as func

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

logger = logging.getLogger()
logger.setLevel(logging.INFO)

FORTIFLEX_API_BASE_URI = "https://support.fortinet.com/ES/api/fortiflex/v2/"
FORTICARE_AUTH_URI = "https://customerapiauth.fortinet.com/api/v1/oauth/token/"

COMMON_HEADERS = {"Content-type": "application/json", "Accept": "application/json"}

FORTIFLEX_REQUESTS = [
    "configs_list",
    "configs_update",
    "entitlements_reactivate",
    "entitlements_stop",
    "get_entitlement_token",
    "programs_list"
]


def requests_post(resource_url, json_body, headers, verify=True):
    """Requests Post"""

    logging.info(resource_url)
    logging.info(json_body)
    logging.info(headers)

    result = requests.post(resource_url, json=json_body, headers=headers, timeout=20, verify=verify)

    if result.ok:
        logging.info(result.content)
        return_value = json.loads(result.content)
    else:
        logging.info(result)
        return_value = None

    logging.info(result.content)
    return return_value


def get_token(username, password, client_id, grant_type):
    """Get Authentication Token"""

    logging.info("--> Retrieving FortiFlex API Token...")

    body = {
        "username": username,
        "password": password,
        "client_id": client_id,
        "grant_type": grant_type,
    }

    results = requests_post(FORTICARE_AUTH_URI, body, COMMON_HEADERS)
    return results

def configs_list(access_token, program_serial_number, account_id=None):
    """List FortiFlex Configurations - V2"""
    logging.info("--> List FortiFlex Configurations...")

    uri = FORTIFLEX_API_BASE_URI + "configs/list"
    headers = COMMON_HEADERS.copy()
    headers["Authorization"] = f"Bearer {access_token}"

    body = {
        "programSerialNumber": program_serial_number,
    }

    # accountId is optional
    if account_id:
        body["accountId"] = account_id

    results = requests_post(uri, body, headers)
    return results

def configs_update(access_token, config_id, name, parameters):
    """Update FortiFlex Configuration - V2"""
    logging.info("--> Update FortiFlex Configuration...")

    uri = FORTIFLEX_API_BASE_URI + "configs/update"
    headers = COMMON_HEADERS.copy()
    headers["Authorization"] = f"Bearer {access_token}"

    body = {
        "id": config_id,
        "name": name,
        "parameters": parameters,
    }

    results = requests_post(uri, body, headers)
    return results

def entitlements_reactivate(access_token, serial_number):
    """Reactivate FortiFlex Entitlement - V2"""
    logging.info("--> Reactivate FortiFlex Entitlement...")

    uri = FORTIFLEX_API_BASE_URI + "entitlements/reactivate"
    headers = COMMON_HEADERS.copy()
    headers["Authorization"] = f"Bearer {access_token}"

    body = {"serialNumber": serial_number}

    results = requests_post(uri, body, headers)
    return results


def entitlements_stop(access_token, serial_number):
    """Stop FortiFlex Entitlement - V2"""
    logging.info("--> Stop FortiFlex Entitlements...")

    uri = FORTIFLEX_API_BASE_URI + "entitlements/stop"
    headers = COMMON_HEADERS.copy()
    headers["Authorization"] = f"Bearer {access_token}"

    body = {"serialNumber": serial_number}

    results = requests_post(uri, body, headers)
    return results

def entitlements_list(access_token, config_id):
    """Retrieve FortiFlex Entitlements List - V2"""
    logging.info("--> Retrieve FortiFlex Entitlements...")

    uri = FORTIFLEX_API_BASE_URI + "entitlements/list"
    headers = COMMON_HEADERS.copy()
    headers["Authorization"] = f"Bearer {access_token}"

    body = {"configId": config_id}

    results = requests_post(uri, body, headers)
    return results

def entitlements_vm_create(access_token, body):
    """Regenerate FortiFlex Entitlement Token - V2"""
    logging.info("--> Regenerate FortiFlex Entitlement Token...")

    uri = FORTIFLEX_API_BASE_URI + "entitlements/vm/create"
    headers = COMMON_HEADERS.copy()
    headers["Authorization"] = f"Bearer {access_token}"

    results = requests_post(uri, body, headers)
    return results


def entitlements_vm_token(access_token, serial_number):
    """Regenerate FortiFlex Entitlement Token - V2"""
    logging.info("--> Regenerate FortiFlex Entitlement Token...")

    uri = FORTIFLEX_API_BASE_URI + "entitlements/vm/token"
    headers = COMMON_HEADERS.copy()
    headers["Authorization"] = f"Bearer {access_token}"

    body = {"serialNumber": serial_number}

    results = requests_post(uri, body, headers)
    return results

def vmlicense_download(vm_ip, entitlement_token, vm_api_key):
    """Send FortiFlex Entitlement Token to FortiGate VM"""
    logging.info("--> Send FortiFlex Entitlement Token to VM...")

    uri = "https://" + f"{vm_ip}/api/v2/monitor/system/vmlicense/download?token={entitlement_token}&access_token={vm_api_key}"

    body = {}

    verify_cert = False
    results = requests_post(uri, body, COMMON_HEADERS, verify_cert)
    return results

def programs_list(access_token):
    """Retrieve FortiFlex Programs List - V2"""
    logging.info("--> Retrieving FortiFlex Programs...")

    uri = FORTIFLEX_API_BASE_URI + "programs/list"
    headers = COMMON_HEADERS.copy()
    headers["Authorization"] = f"Bearer {access_token}"

    results = requests_post(uri, "", headers)
    return results


@app.route(route="flexop")
def flexop(req: func.HttpRequest) -> func.HttpResponse:
    """Flexop"""

    fortiflex_api_token = None
    fortigate_ip_address = None
    fortiflex_access_username = None
    fortiflex_access_password = None
    flex_op = None
    op_resp = None

    return_msg = "FlexOp error: Invalid FlexOp request."

    logging.info("FlexOp request.")
    logging.info(req.method)
    logging.info(req.get_body())

    if req.get_body().decode().find("get_entitlement_token") != -1:
        logging.info("get_entitlement_token request.")
        ip = re.findall( r'[0-9]+(?:\.[0-9]+){3}', req.get_body().decode() )

        logging.info(ip)
        flex_op = "get_entitlement_token"
        fortigate_ip_address = ip[0]
        logging.info(fortigate_ip_address)

    elif req.method == "POST":
        try:
            req_body = req.get_json()
        except ValueError:
            pass
        else:
            flex_op = req_body.get("flexop")

    fortiflex_api_access_token = None

    # Is it valid FlexOp request
    if flex_op in FORTIFLEX_REQUESTS:

        #### Get FortiFlex API Credentials either from headers, body or environment ####
        if "fortiflex_access_username" in req.headers and "fortiflex_access_password" in req.headers:
            logging.info("Getting credentials from request headers.")
            fortiflex_access_username = req.headers.get("fortiflex_access_username")
            fortiflex_access_password = req.headers.get("fortiflex_access_password")

        # if fortiflex_access_username is None or fortiflex_access_password is None:
        #     if "fortiflex_access_username" in req_body and "fortiflex_access_password" in req_body:
        #         logging.info("Getting credentials from request body.")
        #         fortiflex_access_username = req_body.get("fortiflex_access_username")
        #         fortiflex_access_password = req_body.get("fortiflex_access_password")

        if fortiflex_access_username is None and fortiflex_access_password is None:
            logging.info("Getting credentials from environment variables.")
            fortiflex_access_username = os.environ["FORTIFLEX_ACCESS_USERNAME"]
            fortiflex_access_password = os.environ["FORTIFLEX_ACCESS_PASSWORD"]

        log_msg = f"fortiflex creds: {fortiflex_access_username}, {fortiflex_access_password}"
        logging.info(log_msg)

        #### Get Auth Token ####
        ###################################
        fortiflex_api_token = get_token(
            fortiflex_access_username,
            fortiflex_access_password,
            "flexvm",
            "password",
        )
        if fortiflex_api_token:
            fortiflex_api_access_token = fortiflex_api_token["access_token"]

    if fortiflex_api_token is not None:

        if flex_op == "programs_list":
            op_resp = programs_list(fortiflex_api_access_token)
            if op_resp:
                return_msg = json.dumps(op_resp)

        if flex_op == "configs_list":
            program_serial_number = os.environ["FORTIFLEX_PROGRAM_SERIAL"]
            op_resp = configs_list(fortiflex_api_access_token, program_serial_number)
            if op_resp:
                return_msg = json.dumps(op_resp)

        if flex_op in  ("entitlements_reactivate", "entitlements_stop"):
            if "serial_number" in req_body:
                serial_number = req_body.get("serial_number")

                if len(serial_number) == 0:
                    return_msg = f"Serial number is missing for op: {flex_op}."
                else:
                    if flex_op == "entitlements_reactivate":
                        op_resp = entitlements_reactivate(fortiflex_api_access_token, serial_number)
                    else:
                        op_resp = entitlements_stop(fortiflex_api_access_token, serial_number)

                if op_resp:
                    return_msg = json.dumps(op_resp)
            else:
                return_msg = f"Serial number is missing for op: {flex_op}."

        if flex_op == "get_entitlement_token":

            fortiflex_program_serial = os.environ["FORTIFLEX_PROGRAM_SERIAL"]
            fortiflex_config_name = os.environ["FORTIFLEX_CONFIG_NAME"]
            fortigate_api_key = os.environ["FORTIGATE_API_KEY"]
            forticloud_asset_folder = os.environ["FORTICLOUD_ASSET_FOLDER"]

            #fortigate_ip_address = req.headers.get("fortigate_ip_address")

            entitlement_token = None
            stopped_entitlements = False
            fortiflex_config_id = None

            configs_list_resp = configs_list(fortiflex_api_access_token, fortiflex_program_serial)
            if configs_list_resp:
                for config in configs_list_resp["configs"]:
                    if config["name"] == fortiflex_config_name:
                        print(config["name"], config["id"])
                        fortiflex_config_id = config["id"]
                        entitlements_list_resp = entitlements_list(fortiflex_api_access_token, config["id"])
                        if entitlements_list_resp:
                            for entitlement in entitlements_list_resp["entitlements"]:
                                print(entitlement["serialNumber"], entitlement["status"])

                                if entitlement["status"] == "STOPPED":
                                    print("Stopped entitlement found in FortiFlex Configuration: " + fortiflex_config_name)
                                    stopped_entitlements = True
                                    entitlements_reactivate_resp = entitlements_reactivate(fortiflex_api_access_token, entitlement["serialNumber"])
                                    if entitlements_reactivate_resp:
                                        op_resp = entitlements_reactivate_resp
                                        entitlements_vm_token_resp = entitlements_vm_token(fortiflex_api_access_token, entitlement["serialNumber"])
                                        if entitlements_vm_token_resp:
                                            entitlement_token = entitlements_vm_token_resp["entitlements"][0]["token"]
                                    break
            if not stopped_entitlements:
                print("No stopped entitlements found in FortiFlex Configuration: " + fortiflex_config_name)
                entitlement_body = {
                    "configId": fortiflex_config_id,
                    "count": 1,
                    "description": "AutoScale VM",
                    "endDate": None,
                    "folderPath": "My Assets/" + forticloud_asset_folder,
                    "skipPending": False,
                }

                entitlements_vm_create_resp = entitlements_vm_create(fortiflex_api_access_token, entitlement_body)
                if entitlements_vm_create_resp:
                    entitlement_token = entitlements_vm_token_resp["entitlements"][0]["token"]

            if entitlement_token:
                op_resp = entitlement_fortigate_send_resp = vmlicense_download(fortigate_ip_address, entitlement_token, fortigate_api_key)
                if entitlement_fortigate_send_resp:
                    print(json.dumps(entitlement_fortigate_send_resp))
            else:
                print("No entitlement token found.")

            logger.info(op_resp)
            return_msg = json.dumps(op_resp)

        if flex_op == "configs_update":
            if "program_serial_number" in req_body and "account_id" in req_body and "parameters" in req_body and "name" in req_body:
                program_serial_number = req_body.get("program_serial_number")
                account_id = req_body.get("account_id")
                name = req_body.get("name")
                parameters = req_body.get("parameters")
                op_resp = configs_list(fortiflex_api_access_token, program_serial_number, account_id)
                if op_resp:
                    print(json.dumps(op_resp))
                    for config in op_resp["configs"]:

                        # config names are unique in an account
                        if config["name"] == name:

                            # loop through the config parameters to find matches for the supplied config updates
                            for parameter in parameters:
                                for n, config_parameter in enumerate(config["parameters"]):
                                    if parameter["id"] == config_parameter["id"] and parameter["name"] == config_parameter["name"] and parameter["value"] != config_parameter["value"]:
                                        config["parameters"][n]["value"] = parameter["value"]

                            op_resp = configs_update(fortiflex_api_access_token, config["id"], name, config["parameters"])
                            return_msg = json.dumps(op_resp)
            else:
                return_msg = f"Config ID, name, or parameters are missing for op: {flex_op}."

    return func.HttpResponse(
        f"resp: {return_msg}",
        status_code=200,
    )
