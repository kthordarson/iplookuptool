from loguru import logger
import os
import requests

ABUSEIPDBAPIKEY = os.environ.get("ABUSEIPDBAPIKEY")
if not ABUSEIPDBAPIKEY:
    logger.error("missing abuseipdb api key")
    os._exit(-1)


def get_abuseipdb_data(ipaddr, maxdays=30):
    # https://www.abuseipdb.com/api.html
    # https://www.abuseipdb.com/check/[IP]/json?key=[API_KEY]&days=[DAYS]
    headers = {"Key": ABUSEIPDBAPIKEY, "Accept": "application/json"}
    params = {
        "maxAgeInDays": maxdays,
        "ipAddress": ipaddr,
        "verbose": "True",
    }
    response = None
    jsonresp = None
    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check", headers=headers, params=params
        )
        # response = requests.get(f'https://www.abuseipdb.com/check/{ipaddr}/json?key={ABUSEIPDBAPIKEY}&days={maxdays}&verbose', headers=headers, params=params)
    except Exception as e:
        logger.error(f"[!] {e} {type(e)}")
        return None
    if response.status_code == 200:
        try:
            jsonresp = response.json()
        except Exception as e:
            logger.error(f"[!] {e} {type(e)} while parsing json response")
            return None
        if response and jsonresp:
            data = jsonresp
            data["url"] = (
                f"https://www.abuseipdb.com/check/{ipaddr}/json?key={ABUSEIPDBAPIKEY}&days={maxdays}&verbose"
            )
            return data
        else:
            logger.error(
                f"Unknown error for {ipaddr} response: {response} json: {jsonresp}"
            )
            return None
    else:
        logger.warning(f"[!] {response.status_code} {response.reason} for {ipaddr}")
        return None


def get_abuseipdb_info(data):
    # parse data from get_abuseipdb_data
    return None
