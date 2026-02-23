from loguru import logger
import os
import aiohttp
import asyncio

async def get_pulsedrive_data(args) -> list:
    data = []
    PULSEDIVEAPIKEY = os.environ.get("PULSEDIVEAPIKEY")
    if not PULSEDIVEAPIKEY:
        logger.warning("missing api key")
        return data

    if args.ip:
        iplist = [args.ip]
    else:
        iplist = args.ips
    try:
        for ipaddr_ in iplist:
            ipaddr = ''.join(ipaddr_)
            async with aiohttp.ClientSession() as session:
                async with session.get(f"https://pulsedive.com/api/info.php?indicator={ipaddr}&key={PULSEDIVEAPIKEY}", ssl=False) as response:
                    if response.status == 200:
                        try:
                            jsonresp = await response.json()
                        except Exception as e:
                            logger.error(f"[!] {e} {type(e)} while parsing json response")
                            await asyncio.sleep(1)
                            continue
                        if jsonresp:
                            data.append(jsonresp)
                        else:
                            logger.error(f"Unknown error for {ipaddr} json: {jsonresp}")
                            await asyncio.sleep(1)
                            continue
                    elif response.status == 404:
                        if args.debug:
                            text = await response.text()
                            logger.warning(f"[!] not found {ipaddr} {text}")  # type: ignore
                        await asyncio.sleep(1)
                        continue
                    else:
                        logger.warning(f"[!] {response.status} {response.reason} for {ipaddr}")
                        if args.debug:
                            logger.warning(f"text: {await response.text()}")
                        await asyncio.sleep(1)
                        continue
    except Exception as e:
        logger.error(f"[!] {e} {type(e)}")
    return data
