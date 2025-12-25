from loguru import logger
import os
import aiohttp

ALIENTVAULTAPIKEY = os.environ.get("ALIENTVAULTAPIKEY")
if not ALIENTVAULTAPIKEY:
    logger.warning("missing crowdsec api key")
    # os._exit(-1)


async def get_alienvault_data(args):
    if ALIENTVAULTAPIKEY:
        headers = {"x-api-key": ALIENTVAULTAPIKEY}
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"https://otx.alienvault.com/api/v1/indicators/IPv4/{args.ip}", headers=headers) as response:
                    if response.status == 200:
                        try:
                            jsonresp = await response.json()
                        except Exception as e:
                            logger.error(
                                f"[!] {e} {type(e)} while parsing json response"
                            )
                            return None
                        if jsonresp:
                            data = jsonresp
                            return data
                        else:
                            logger.error(
                                f"Unknown error for {args.ip} json: {jsonresp}"
                            )
                            return None
                    elif response.status == 404:
                        if args.debug:
                            text = await response.text()
                            logger.warning(f"[!] not found {args.ip} {text}")  # type: ignore
                        return None
                    else:
                        logger.warning(
                            f"[!] {response.status} {response.reason} for {args.ip}"
                        )
                        if args.debug:
                            logger.warning(f"headers: {response.headers}")
                            logger.warning(f"text: {await response.text()}")
                        return None
        except Exception as e:
            logger.error(f"[!] {e} {type(e)}")
            return None
