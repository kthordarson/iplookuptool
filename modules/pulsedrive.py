from loguru import logger
import os
import aiohttp

PULSEDIVEAPIKEY = os.environ.get("PULSEDIVEAPIKEY")
if not PULSEDIVEAPIKEY:
    logger.warning("missing api key")
    # os._exit(-1)


async def get_pulsedrive_data(args):
    if PULSEDIVEAPIKEY:
        headers = {"x-api-key": PULSEDIVEAPIKEY}
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"https://pulsedive.com/api/info.php?indicator={args.ip}&key={PULSEDIVEAPIKEY}", headers=headers) as response:
                    if response.status == 200:
                        try:
                            jsonresp = await response.json()
                        except Exception as e:
                            logger.error(f"[!] {e} {type(e)} while parsing json response")
                            return None
                        if jsonresp:
                            data = jsonresp
                            return data
                        else:
                            logger.error(f"Unknown error for {args.ip} json: {jsonresp}")
                            return None
                    elif response.status == 404:
                        if args.debug:
                            text = await response.text()
                            logger.warning(f"[!] not found {args.ip} {text}")  # type: ignore
                        return None
                    else:
                        logger.warning(f"[!] {response.status} {response.reason} for {args.ip}")
                        if args.debug:
                            logger.warning(f"headers: {response.headers}")
                            logger.warning(f"text: {await response.text()}")
                        return None
        except Exception as e:
            logger.error(f"[!] {e} {type(e)}")
            return None
