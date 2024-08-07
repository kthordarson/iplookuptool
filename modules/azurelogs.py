from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient, LogsQueryStatus
import pandas as pd
import os
from datetime import timedelta
from loguru import logger


def get_azure_signinlogs(ipaddress, resulttype=0):
    creds = DefaultAzureCredential()
    logclient = LogsQueryClient(creds)
    query = f'SigninLogs | where IPAddress == "{ipaddress}" | where ResultType == "{resulttype}" | take 100'
    logs_resource_id = os.getenv('AZURE_LOGRESOURCE_ID')
    response = logclient.query_resource(logs_resource_id, query, timespan=timedelta(days=1))
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

def get_azure_signinlogs_failed(ipaddress):
    creds = DefaultAzureCredential()
    logclient = LogsQueryClient(creds)
    query = f'SigninLogs | where IPAddress == "{ipaddress}" | where ResultType != "0" | take 100'
    logs_resource_id = os.getenv('AZURE_LOGRESOURCE_ID')
    response = logclient.query_resource(logs_resource_id, query, timespan=timedelta(days=1))
    if response.status == LogsQueryStatus.PARTIAL:
        error = response.partial_error
        # data = response.partial_data
        logger.error(f'[!] partial {error}')
    elif response.status == LogsQueryStatus.SUCCESS:
        # data = response.tables
        for table in response.tables:
            df = pd.DataFrame(table.rows, columns=[col for col in table.columns])
            key_value = df.to_dict(orient='records')
            
        # df = pd.DataFrame(data=data[0].rows, columns=data[0].columns)
        # d = json.loads(df.to_json())
        return key_value

if __name__ == '__main__':
    pass