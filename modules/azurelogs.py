import traceback
from azure.identity.aio import DefaultAzureCredential
from azure.monitor.query.aio import LogsQueryClient
from azure.monitor.query import LogsQueryStatus
import pandas as pd
import os
from datetime import timedelta
from loguru import logger


async def get_azure_signinlogs(args, resulttype=0):
    if not os.getenv('AZURE_LOGRESOURCE_ID'):
        logger.error('AZURE_LOGRESOURCE_ID environment variable not set')
        return []
    try:
        key_value = []
        async with DefaultAzureCredential() as creds:
            async with LogsQueryClient(creds) as logclient:
                query = f'SigninLogs | where IPAddress == "{args.ipaddress}" | take 100'
                logs_resource_id = os.getenv('AZURE_LOGRESOURCE_ID')
                response = await logclient.query_resource(logs_resource_id, query, timespan=timedelta(days=1))  # type: ignore
                if response.status == LogsQueryStatus.PARTIAL:
                    error = response.partial_error
                    # data = response.partial_data
                    logger.error(f'[!] partial {error}\n{query=}')
                    return []
                elif response.status == LogsQueryStatus.SUCCESS:
                    # data = response.tables
                    for table in response.tables:
                        df = pd.DataFrame(table.rows, columns=[col for col in table.columns])
                        key_value = df.to_dict(orient='records')
                    # df = pd.DataFrame(data=data[0].rows, columns=data[0].columns)
                    # d = json.loads(df.to_json())
                    return key_value
                else:
                    logger.error(f'Unexpected response status: {response.status}')
                    return []
    except Exception as e:
        logger.error(f"azure logs exception: {e} {type(e)} for {args.ipaddress}")
        if args.debug:
            logger.error(traceback.format_exc())
        return []

async def get_azure_signinlogs_failed(args):
    if not os.getenv('AZURE_LOGRESOURCE_ID'):
        logger.error('AZURE_LOGRESOURCE_ID environment variable not set')
        return []
    key_value = []
    async with DefaultAzureCredential() as creds:
        async with LogsQueryClient(creds) as logclient:
            query = f'SigninLogs | where IPAddress == "{args.ipaddress}" | where ResultType != "0" | take 100'
            logs_resource_id = os.getenv('AZURE_LOGRESOURCE_ID')
            response = await logclient.query_resource(logs_resource_id, query, timespan=timedelta(days=1))  # type: ignore
            if response.status == LogsQueryStatus.PARTIAL:
                error = response.partial_error
                # data = response.partial_data
                logger.error(f'[!] partial {error}')
                return []
            elif response.status == LogsQueryStatus.SUCCESS:
                # data = response.tables
                for table in response.tables:
                    df = pd.DataFrame(table.rows, columns=[col for col in table.columns])
                    key_value = df.to_dict(orient='records')
                # df = pd.DataFrame(data=data[0].rows, columns=data[0].columns)
                # d = json.loads(df.to_json())
                return key_value
            else:
                logger.error(f'Unexpected response status: {response.status}')
                return []

if __name__ == '__main__':
    pass
