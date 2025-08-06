import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime, timedelta


def create_sample_data(size=100, data_type="basic"):
    """
    Create a sample dataset for testing and demonstration
    
    Args:
        size: Number of rows in the sample dataset
        data_type: Type of sample data to create ("basic" or "network_events")
        
    Returns:
        pandas DataFrame with sample data
    """
    if data_type == "network_events":
        # Generate more realistic network events data similar to Defender/Security logs
        timestamps = [(datetime.now() - timedelta(hours=np.random.randint(0, 24))).strftime('%Y-%m-%dT%H:%M:%S.%fZ') 
                       for _ in range(size)]
        
        device_ids = [f"{np.random.randint(100000, 999999):x}" + 
                      f"{np.random.randint(100000, 999999):x}" +
                      f"{np.random.randint(100000, 999999):x}" +
                      f"{np.random.randint(100000, 999999):x}" +
                      f"{np.random.randint(100000, 999999):x}"
                      for _ in range(20)]
                      
        device_names = [f"srv{i:02d}.example.com" for i in range(20)]
        
        remote_ips = ['192.168.1.' + str(i) for i in range(1, 21)] + \
                     ['10.0.0.' + str(i) for i in range(1, 11)] + \
                     ['172.16.0.' + str(i) for i in range(1, 11)] + \
                     ['8.8.8.8', '1.1.1.1', '20.166.40.71', '52.236.189.96']
                     
        process_names = ['w3wp.exe', 'svchost.exe', 'cmd.exe', 'powershell.exe', 'iexplore.exe', 'chrome.exe']
        
        app_pools = [f"{name}-Pool" for name in ['Default', 'API', 'WebService', 'Frontend', 'Backend']]
        
        command_lines = [
            f'w3wp.exe -ap "{pool}" -v "v4.0" -l "webengine4.dll" -a \\\\pipe\\{np.random.randint(1000, 9999)} -h "C:\\inetpub\\temp\\{pool}.config" -w "" -m 0 -t {np.random.choice([20, 60, 120])}'
            for pool in app_pools
        ]
        
        return pd.DataFrame({
            '$table': ['DeviceNetworkEvents'] * size,
            'Timestamp': np.random.choice(timestamps, size=size),
            'DeviceId': np.random.choice(device_ids, size=size),
            'DeviceName': np.random.choice(device_names, size=size),
            'ActionType': np.random.choice(['ConnectionSuccess', 'ConnectionFailed'], size=size, p=[0.9, 0.1]),
            'RemoteIP': np.random.choice(remote_ips, size=size),
            'RemotePort': np.random.choice([80, 443, 8080, 9000, 3389, 22, 1433, 3306], size=size),
            'LocalIP': np.random.choice(['192.168.1.' + str(i) for i in range(50, 70)], size=size),
            'LocalPort': np.random.randint(10000, 65000, size=size),
            'Protocol': np.random.choice(['Tcp', 'Udp'], size=size, p=[0.95, 0.05]),
            'InitiatingProcessFileName': np.random.choice(process_names, size=size),
            'InitiatingProcessFileSize': np.random.randint(1000, 50000, size=size),
            'InitiatingProcessCommandLine': np.random.choice(command_lines, size=size),
            'InitiatingProcessId': np.random.randint(1000, 50000, size=size)
        })
    else:
        # Original basic sample data
        return pd.DataFrame({
            'RemoteIP': np.random.choice(['192.168.1.1', '10.0.0.1', '172.16.0.1'], size=size),
            'RemotePort': np.random.choice([80, 443, 8080, 9000], size=size),
            'InitiatingProcessFileName': np.random.choice(['w3wp.exe', 'svchost.exe', 'cmd.exe'], size=size),
            'InitiatingProcessFileSize': np.random.randint(1000, 50000, size=size),
            'InitiatingProcessCommandLine': np.random.choice(['cmd /c whoami', 'powershell -enc ...', 'w3wp.exe -ap ...'], size=size)
        })


def analyze_dataset(df=None, data_type="basic", show_plots=True):
    """
    Analyze a dataset with network and process information
    
    Args:
        df: pandas DataFrame to analyze. If None, a sample dataset will be created.
        data_type: Type of data to analyze ("basic" or "network_events")
        show_plots: Whether to display plots during analysis
        
    Returns:
        Dictionary containing analysis results
    """
    # Create sample data if none provided
    if df is None:
        df = create_sample_data(data_type=data_type)
    
    # Determine if this is network events data by checking for key columns
    is_network_events = all(col in df.columns for col in ['$table', 'Timestamp', 'DeviceId', 'ActionType'])
    
    if is_network_events:
        return analyze_network_events(df, show_plots)
    else:
        return analyze_basic_data(df, show_plots)


def analyze_basic_data(df, show_plots=True):
    """
    Analyze basic network and process data
    
    Args:
        df: pandas DataFrame to analyze
        show_plots: Whether to display plots during analysis
        
    Returns:
        Dictionary containing analysis results
    """
    # 1. Group by Remote IP
    ip_counts = df['RemoteIP'].value_counts().reset_index()
    ip_counts.columns = ['RemoteIP', 'Count']

    # 2. Group by Remote Port
    port_counts = df['RemotePort'].value_counts().reset_index()
    port_counts.columns = ['RemotePort', 'Count']

    # 3. Group by Process Name
    process_counts = df['InitiatingProcessFileName'].value_counts().reset_index()
    process_counts.columns = ['ProcessName', 'Count']

    # 4. Detect outliers in file size
    Q1 = df['InitiatingProcessFileSize'].quantile(0.25)
    Q3 = df['InitiatingProcessFileSize'].quantile(0.75)
    IQR = Q3 - Q1
    outliers = df[(df['InitiatingProcessFileSize'] < Q1 - 1.5 * IQR) | (df['InitiatingProcessFileSize'] > Q3 + 1.5 * IQR)]

    # 5. Unique command lines
    unique_cmds = df['InitiatingProcessCommandLine'].value_counts().reset_index()
    unique_cmds.columns = ['CommandLine', 'Count']

    if show_plots:
        # 6. Visualizations
        plt.figure(figsize=(10, 5))
        sns.barplot(data=ip_counts, x='RemoteIP', y='Count')
        plt.title('Top Remote IPs')
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.show()

        plt.figure(figsize=(10, 5))
        sns.histplot(df['RemotePort'], bins=10, kde=False)
        plt.title('Remote Port Distribution')
        plt.show()

        plt.figure(figsize=(10, 5))
        sns.boxplot(x=df['InitiatingProcessFileSize'])
        plt.title('File Size Distribution with Outliers')
        plt.show()

    # Collect results
    results = {
        "ip_counts": ip_counts,
        "port_counts": port_counts,
        "process_counts": process_counts,
        "outliers": outliers,
        "unique_cmds": unique_cmds
    }
    
    # Print summaries
    print("Top Remote IPs:\n", ip_counts.head())
    print("\nTop Remote Ports:\n", port_counts.head())
    print("\nTop Process Names:\n", process_counts.head())
    print("\nOutliers in File Size:\n", outliers[['InitiatingProcessFileName', 'InitiatingProcessFileSize']])
    print("\nUnique Command Lines:\n", unique_cmds.head())
    
    return results


def analyze_network_events(df, show_plots=True):
    """
    Analyze network events data from security products like Microsoft Defender
    
    Args:
        df: pandas DataFrame containing network events data
        show_plots: Whether to display plots during analysis
        
    Returns:
        Dictionary containing analysis results
    """
    results = {}
    
    # Convert timestamp to datetime for time-based analysis
    if 'Timestamp' in df.columns:
        df['Timestamp'] = pd.to_datetime(df['Timestamp'])
        
        # Add hour and day columns for time-based analysis
        df['Hour'] = df['Timestamp'].dt.hour
        df['Day'] = df['Timestamp'].dt.day_name()
        
        # Time-based analysis
        hourly_connections = df.groupby('Hour').size().reset_index(name='Count')
        daily_connections = df.groupby('Day').size().reset_index(name='Count')
        
        results['hourly_connections'] = hourly_connections
        results['daily_connections'] = daily_connections
        
        if show_plots:
            # Hourly distribution
            plt.figure(figsize=(12, 6))
            sns.barplot(x='Hour', y='Count', data=hourly_connections)
            plt.title('Hourly Distribution of Network Connections')
            plt.xlabel('Hour of Day')
            plt.ylabel('Number of Connections')
            plt.show()
            
            # Daily distribution
            days_order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
            if not daily_connections.empty and 'Day' in daily_connections.columns:
                daily_connections['Day'] = pd.Categorical(daily_connections['Day'], 
                                                         categories=days_order, 
                                                         ordered=True)
                daily_connections = daily_connections.sort_values('Day')
                
                plt.figure(figsize=(12, 6))
                sns.barplot(x='Day', y='Count', data=daily_connections)
                plt.title('Daily Distribution of Network Connections')
                plt.xlabel('Day of Week')
                plt.ylabel('Number of Connections')
                plt.show()
    
    # 1. Device analysis
    if 'DeviceName' in df.columns:
        device_counts = df['DeviceName'].value_counts().reset_index()
        device_counts.columns = ['DeviceName', 'Count']
        results['device_counts'] = device_counts
        
        if show_plots and not device_counts.empty:
            plt.figure(figsize=(14, 6))
            top_devices = device_counts.head(20)  # Show top 20 devices
            sns.barplot(x='DeviceName', y='Count', data=top_devices)
            plt.title('Top Devices by Connection Count')
            plt.xticks(rotation=45, ha='right')
            plt.tight_layout()
            plt.show()
        
        print("Top Devices by Connection Count:\n", device_counts.head(10))
    
    # 2. Connection status analysis
    if 'ActionType' in df.columns:
        action_counts = df['ActionType'].value_counts().reset_index()
        action_counts.columns = ['ActionType', 'Count']
        results['action_counts'] = action_counts
        
        if show_plots and not action_counts.empty:
            plt.figure(figsize=(10, 5))
            sns.barplot(x='ActionType', y='Count', data=action_counts)
            plt.title('Connection Outcomes')
            plt.show()
            
        print("\nConnection Outcomes:\n", action_counts)
    
    # 3. IP address analysis
    if 'RemoteIP' in df.columns:
        ip_counts = df['RemoteIP'].value_counts().reset_index()
        ip_counts.columns = ['RemoteIP', 'Count']
        results['ip_counts'] = ip_counts
        
        if 'RemoteIPType' in df.columns:
            iptype_counts = df['RemoteIPType'].value_counts().reset_index()
            iptype_counts.columns = ['RemoteIPType', 'Count']
            results['iptype_counts'] = iptype_counts
            
            if show_plots and not iptype_counts.empty:
                plt.figure(figsize=(10, 5))
                sns.barplot(x='RemoteIPType', y='Count', data=iptype_counts)
                plt.title('Remote IP Types')
                plt.show()
                
            print("\nRemote IP Types:\n", iptype_counts)
            
        if show_plots and not ip_counts.empty:
            plt.figure(figsize=(14, 6))
            top_ips = ip_counts.head(20)
            sns.barplot(x='RemoteIP', y='Count', data=top_ips)
            plt.title('Top Remote IPs')
            plt.xticks(rotation=45, ha='right')
            plt.tight_layout()
            plt.show()
            
        print("\nTop Remote IPs:\n", ip_counts.head(10))
    
    # 4. Port analysis
    if 'RemotePort' in df.columns:
        port_counts = df['RemotePort'].value_counts().reset_index()
        port_counts.columns = ['RemotePort', 'Count']
        results['port_counts'] = port_counts
        
        if show_plots and not port_counts.empty:
            plt.figure(figsize=(12, 6))
            top_ports = port_counts.head(15)
            sns.barplot(x='RemotePort', y='Count', data=top_ports)
            plt.title('Top Remote Ports')
            plt.show()
            
        print("\nTop Remote Ports:\n", port_counts.head(10))
    
    # 5. Process analysis
    if 'InitiatingProcessFileName' in df.columns:
        process_counts = df['InitiatingProcessFileName'].value_counts().reset_index()
        process_counts.columns = ['ProcessName', 'Count']
        results['process_counts'] = process_counts
        
        if show_plots and not process_counts.empty:
            plt.figure(figsize=(12, 6))
            top_processes = process_counts.head(15)
            sns.barplot(x='ProcessName', y='Count', data=top_processes)
            plt.title('Top Processes Initiating Connections')
            plt.xticks(rotation=45, ha='right')
            plt.tight_layout()
            plt.show()
            
        print("\nTop Processes Initiating Connections:\n", process_counts.head(10))
    
    # 6. Web application pool analysis for IIS processes
    if 'InitiatingProcessCommandLine' in df.columns and df['InitiatingProcessCommandLine'].str.contains('-ap').any():
        # Extract app pool names from command lines
        app_pools = []
        for cmd in df['InitiatingProcessCommandLine']:
            if isinstance(cmd, str) and '-ap' in cmd:
                match = cmd.split('-ap')[1].split('"')[1] if '"' in cmd.split('-ap')[1] else cmd.split('-ap')[1].strip().split()[0]
                app_pools.append(match)
            else:
                app_pools.append('Unknown')
        
        df['AppPool'] = app_pools
        apppool_counts = df['AppPool'].value_counts().reset_index()
        apppool_counts.columns = ['AppPool', 'Count']
        results['apppool_counts'] = apppool_counts
        
        if show_plots and not apppool_counts.empty:
            plt.figure(figsize=(14, 6))
            top_apppools = apppool_counts.head(15)
            sns.barplot(x='AppPool', y='Count', data=top_apppools)
            plt.title('Top IIS Application Pools')
            plt.xticks(rotation=45, ha='right')
            plt.tight_layout()
            plt.show()
            
        print("\nTop IIS Application Pools:\n", apppool_counts.head(10))
    
    # 7. Connection patterns (IP to Port combinations)
    if all(col in df.columns for col in ['RemoteIP', 'RemotePort']):
        df['IP_Port'] = df['RemoteIP'] + ':' + df['RemotePort'].astype(str)
        ip_port_counts = df['IP_Port'].value_counts().reset_index()
        ip_port_counts.columns = ['IP_Port', 'Count']
        results['ip_port_counts'] = ip_port_counts
        
        print("\nTop IP:Port Combinations:\n", ip_port_counts.head(10))
    
    return results


def show_interactive_plots(data=None, data_type="basic"):
    """
    Display interactive plots for the dataset
    
    Args:
        data: Data to visualize. Can be a pandas DataFrame or a results dictionary from analyze_dataset.
              If None, a sample dataset will be created.
        data_type: Type of data to visualize ("basic" or "network_events")
    """
    # Check if the input is a dictionary (likely results from analyze_dataset)
    if isinstance(data, dict):
        # Extract DataFrames from the results dictionary
        if data_type == "network_events":
            show_network_events_plots_from_results(data)
        else:
            show_basic_plots_from_results(data)
        return
    
    # If data is None or a DataFrame
    df = data if data is not None else create_sample_data(data_type=data_type)
    
    # Check if df is a DataFrame
    if not isinstance(df, pd.DataFrame):
        print(f"Error: Expected a DataFrame or results dictionary, got {type(df)}")
        return
    
    # Determine if this is network events data by checking for key columns
    is_network_events = all(col in df.columns for col in ['$table', 'Timestamp', 'DeviceId', 'ActionType'])
    
    if is_network_events:
        show_network_events_plots(df)
    else:
        show_basic_plots(df)


def show_basic_plots_from_results(results):
    """
    Display interactive plots for basic data using results dictionary
    
    Args:
        results: Dictionary containing analysis results from analyze_basic_data
    """
    # Check if we have the necessary result keys
    if not all(key in results for key in ["ip_counts", "port_counts"]):
        print("Error: Results dictionary doesn't have the required keys for plotting basic data")
        return
    
    # 1. Interactive bar plot for IP counts
    plt.figure(figsize=(10, 5))
    sns.barplot(data=results["ip_counts"], x='RemoteIP', y='Count')
    plt.title('Top Remote IPs')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()

    # 2. Port counts
    plt.figure(figsize=(10, 5))
    sns.barplot(data=results["port_counts"], x='RemotePort', y='Count')
    plt.title('Remote Port Distribution')
    plt.show()

    # 3. Process counts if available
    if "process_counts" in results:
        plt.figure(figsize=(12, 6))
        sns.barplot(data=results["process_counts"], x='ProcessName', y='Count')
        plt.title('Top Processes')
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        plt.show()


def show_network_events_plots_from_results(results):
    """
    Display interactive plots for network events data using results dictionary
    
    Args:
        results: Dictionary containing analysis results from analyze_network_events
    """
    # Time-based visualizations
    if all(key in results for key in ["hourly_connections", "daily_connections"]):
        # Hourly connection counts
        plt.figure(figsize=(14, 6))
        hourly_counts = results["hourly_connections"]
        sns.lineplot(x='Hour', y='Count', data=hourly_counts, marker='o')
        plt.title('Connections by Hour of Day')
        plt.xlabel('Hour')
        plt.ylabel('Number of Connections')
        plt.xticks(range(0, 24))
        plt.grid(True, linestyle='--', alpha=0.7)
        plt.show()
        
        # Daily connection counts
        days_order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
        daily_counts = results["daily_connections"].copy()
        if 'Day' in daily_counts.columns:
            daily_counts['Day'] = pd.Categorical(daily_counts['Day'], categories=days_order, ordered=True)
            daily_counts = daily_counts.sort_values('Day')
            
            plt.figure(figsize=(14, 6))
            sns.barplot(x='Day', y='Count', data=daily_counts)
            plt.title('Connections by Day of Week')
            plt.xlabel('Day')
            plt.ylabel('Number of Connections')
            plt.grid(True, linestyle='--', alpha=0.7)
            plt.show()
    
    # Device analysis
    if "device_counts" in results and not results["device_counts"].empty:
        plt.figure(figsize=(14, 8))
        device_counts = results["device_counts"].head(15)  # Show top 15 devices
        sns.barplot(x='DeviceName', y='Count', data=device_counts)
        plt.title('Top 15 Devices by Connection Count')
        plt.xlabel('Device Name')
        plt.ylabel('Number of Connections')
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        plt.show()
    
    # Connection outcomes
    if "action_counts" in results and not results["action_counts"].empty:
        plt.figure(figsize=(10, 6))
        action_counts = results["action_counts"].set_index('ActionType')['Count']
        plt.pie(action_counts, labels=action_counts.index, autopct='%1.1f%%', 
                startangle=90, shadow=True, explode=[0.05] * len(action_counts))
        plt.title('Connection Outcomes')
        plt.axis('equal')
        plt.show()
    
    # IP analysis
    if "ip_counts" in results and not results["ip_counts"].empty:
        plt.figure(figsize=(14, 6))
        top_ips = results["ip_counts"].head(20)
        sns.barplot(x='RemoteIP', y='Count', data=top_ips)
        plt.title('Top Remote IPs')
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        plt.show()
    
    # IP types
    if "iptype_counts" in results and not results["iptype_counts"].empty:
        plt.figure(figsize=(10, 6))
        iptype_counts = results["iptype_counts"].set_index('RemoteIPType')['Count']
        plt.pie(iptype_counts, labels=iptype_counts.index, autopct='%1.1f%%', 
                startangle=90, shadow=True, explode=[0.05] * len(iptype_counts))
        plt.title('Remote IP Types')
        plt.axis('equal')
        plt.show()
    
    # Port analysis
    if "port_counts" in results and not results["port_counts"].empty:
        plt.figure(figsize=(14, 8))
        port_counts = results["port_counts"].head(15)
        sns.barplot(x='RemotePort', y='Count', data=port_counts)
        plt.title('Top 15 Remote Ports')
        plt.xlabel('Port')
        plt.ylabel('Connection Count')
        plt.tight_layout()
        plt.show()
    
    # Process analysis
    if "process_counts" in results and not results["process_counts"].empty:
        plt.figure(figsize=(12, 6))
        process_counts = results["process_counts"].head(15)
        sns.barplot(x='ProcessName', y='Count', data=process_counts)
        plt.title('Top Processes Initiating Connections')
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        plt.show()
    
    # App Pool analysis
    if "apppool_counts" in results and not results["apppool_counts"].empty:
        plt.figure(figsize=(14, 8))
        apppool_counts = results["apppool_counts"].head(15)
        sns.barplot(x='AppPool', y='Count', data=apppool_counts)
        plt.title('Top 15 IIS Application Pools')
        plt.xlabel('Application Pool')
        plt.ylabel('Connection Count')
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        plt.show()


def show_basic_plots(df):
    """
    Display interactive plots for basic data
    
    Args:
        df: pandas DataFrame to visualize
    """
    # Get analysis results (without showing plots during analysis)
    results = analyze_basic_data(df, show_plots=False)
    
    # 1. Interactive bar plot for IP counts
    plt.figure(figsize=(10, 5))
    sns.barplot(data=results["ip_counts"], x='RemoteIP', y='Count')
    plt.title('Top Remote IPs')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()

    # 2. Port distribution
    plt.figure(figsize=(10, 5))
    sns.histplot(df['RemotePort'], bins=10, kde=False)
    plt.title('Remote Port Distribution')
    plt.show()

    # 3. File size boxplot
    plt.figure(figsize=(10, 5))
    sns.boxplot(x=df['InitiatingProcessFileSize'])
    plt.title('File Size Distribution with Outliers')
    plt.show()


def show_network_events_plots(df):
    """
    Display interactive plots for network events data
    
    Args:
        df: pandas DataFrame containing network events data
    """
    # 1. Time-based visualizations
    if 'Timestamp' in df.columns:
        df['Timestamp'] = pd.to_datetime(df['Timestamp'])
        df['Hour'] = df['Timestamp'].dt.hour
        df['Day'] = df['Timestamp'].dt.day_name()
        
        # Hourly connection counts
        plt.figure(figsize=(14, 6))
        hourly_counts = df.groupby('Hour').size().reset_index(name='Count')
        sns.lineplot(x='Hour', y='Count', data=hourly_counts, marker='o')
        plt.title('Connections by Hour of Day')
        plt.xlabel('Hour')
        plt.ylabel('Number of Connections')
        plt.xticks(range(0, 24))
        plt.grid(True, linestyle='--', alpha=0.7)
        plt.show()
        
        # Daily connection counts
        days_order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
        daily_counts = df.groupby('Day').size().reset_index(name='Count')
        daily_counts['Day'] = pd.Categorical(daily_counts['Day'], categories=days_order, ordered=True)
        daily_counts = daily_counts.sort_values('Day')
        
        plt.figure(figsize=(14, 6))
        sns.barplot(x='Day', y='Count', data=daily_counts)
        plt.title('Connections by Day of Week')
        plt.xlabel('Day')
        plt.ylabel('Number of Connections')
        plt.grid(True, linestyle='--', alpha=0.7)
        plt.show()
    
    # 2. Connection outcome analysis
    if 'ActionType' in df.columns:
        plt.figure(figsize=(10, 6))
        action_counts = df['ActionType'].value_counts()
        plt.pie(action_counts, labels=action_counts.index, autopct='%1.1f%%', 
                startangle=90, shadow=True, explode=[0.05] * len(action_counts))
        plt.title('Connection Outcomes')
        plt.axis('equal')
        plt.show()
    
    # 3. Top devices visualization
    if 'DeviceName' in df.columns:
        plt.figure(figsize=(14, 8))
        device_counts = df['DeviceName'].value_counts().nlargest(15)
        sns.barplot(x=device_counts.index, y=device_counts.values)
        plt.title('Top 15 Devices by Connection Count')
        plt.xlabel('Device Name')
        plt.ylabel('Number of Connections')
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        plt.show()
    
    # 4. IP Type distribution
    if 'RemoteIPType' in df.columns:
        plt.figure(figsize=(10, 6))
        iptype_counts = df['RemoteIPType'].value_counts()
        plt.pie(iptype_counts, labels=iptype_counts.index, autopct='%1.1f%%', 
                startangle=90, shadow=True, explode=[0.05] * len(iptype_counts))
        plt.title('Remote IP Types')
        plt.axis('equal')
        plt.show()
    
    # 5. Top ports visualization
    if 'RemotePort' in df.columns:
        plt.figure(figsize=(14, 8))
        port_counts = df['RemotePort'].value_counts().nlargest(15)
        sns.barplot(x=port_counts.index.astype(str), y=port_counts.values)
        plt.title('Top 15 Remote Ports')
        plt.xlabel('Port')
        plt.ylabel('Connection Count')
        plt.tight_layout()
        plt.show()
        
        # Port heatmap by hour
        if 'Hour' in df.columns:
            top_ports = df['RemotePort'].value_counts().nlargest(10).index
            port_hour_df = df[df['RemotePort'].isin(top_ports)]
            port_hour_pivot = pd.crosstab(port_hour_df['Hour'], port_hour_df['RemotePort'])
            
            plt.figure(figsize=(16, 8))
            sns.heatmap(port_hour_pivot, cmap='YlGnBu', annot=True, fmt='d', linewidths=.5)
            plt.title('Connection Counts by Hour and Port')
            plt.xlabel('Port')
            plt.ylabel('Hour of Day')
            plt.show()
    
    # 6. Process information
    if all(col in df.columns for col in ['InitiatingProcessFileName', 'RemotePort']):
        # Process to port mapping visualization
        top_processes = df['InitiatingProcessFileName'].value_counts().nlargest(5).index
        top_ports = df['RemotePort'].value_counts().nlargest(5).index
        
        process_port_df = df[df['InitiatingProcessFileName'].isin(top_processes) & 
                            df['RemotePort'].isin(top_ports)]
        
        process_port_pivot = pd.crosstab(
            process_port_df['InitiatingProcessFileName'], 
            process_port_df['RemotePort']
        )
        
        plt.figure(figsize=(14, 8))
        sns.heatmap(process_port_pivot, cmap='YlGnBu', annot=True, fmt='d', linewidths=.5)
        plt.title('Connection Counts by Process and Port')
        plt.xlabel('Port')
        plt.ylabel('Process')
        plt.tight_layout()
        plt.show()
    
    # 7. App Pool visualization if we have IIS data
    if 'InitiatingProcessCommandLine' in df.columns and df['InitiatingProcessCommandLine'].str.contains('-ap').any():
        # Extract app pool names from command lines
        app_pools = []
        for cmd in df['InitiatingProcessCommandLine']:
            if isinstance(cmd, str) and '-ap' in cmd:
                match = cmd.split('-ap')[1].split('"')[1] if '"' in cmd.split('-ap')[1] else cmd.split('-ap')[1].strip().split()[0]
                app_pools.append(match)
            else:
                app_pools.append('Unknown')
        
        df['AppPool'] = app_pools
        
        plt.figure(figsize=(14, 8))
        apppool_counts = df['AppPool'].value_counts().nlargest(15)
        sns.barplot(x=apppool_counts.index, y=apppool_counts.values)
        plt.title('Top 15 IIS Application Pools')
        plt.xlabel('Application Pool')
        plt.ylabel('Connection Count')
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        plt.show()


# This will be executed when run directly in IPython
if __name__ == "__main__" or '__file__' not in globals():
    print("Dataset Analysis Tool")
    print("====================")
    
    # Check if this is run in IPython (different interactive behavior)
    try:
        # Using the special variable that's defined in IPython but not in regular Python
        shell = globals().get('__builtins__', {}).get('__IPYTHON__', False)
        # Alternative method that works directly when running in IPython
        if not shell:
            # This will raise NameError if we're not in IPython
            shell = eval('__IPYTHON__')
        is_ipython = True
    except (NameError, AttributeError):
        is_ipython = False
    
    # Choose data type
    if not is_ipython:
        print("\nSelect data type to analyze:")
        print("1. Basic network data")
        print("2. Network events data (like Defender/Security logs)")
        
        try:
            choice = int(input("Enter choice (1 or 2): "))
            data_type = "basic" if choice == 1 else "network_events"
            size = int(input("Enter sample size (default 100): ") or 100)
        except ValueError:
            print("Invalid input, using default: basic data with size 100")
            data_type = "basic"
            size = 100
    else:
        # In IPython mode, use network_events data type by default
        data_type = "network_events"
        size = 100
        print(f"Running in IPython mode with {data_type} data type")
    
    # Create sample data
    sample_df = create_sample_data(size=size, data_type=data_type)
    print(f"\nSample {data_type} dataset created with shape:", sample_df.shape)
    
    # Display head of the data
    print("\nSample data preview:")
    print(sample_df.head())
    
    # Run analysis
    print("\nRunning analysis...")
    results = analyze_dataset(sample_df, data_type=data_type, show_plots=False)
    
    # Show visualizations
    print("\nDisplaying interactive plots...")
    
    # Allow visualizing either the original data or the results
    if is_ipython:
        print("Note: You can visualize your data by calling:")
        print("- show_interactive_plots(df) with your DataFrame")
        print("- show_interactive_plots(results) with analysis results")
        # In IPython we'll visualize both for convenience
        show_interactive_plots(sample_df, data_type=data_type)
        print("\nVisualization from results dictionary:")
        show_interactive_plots(results, data_type=data_type)
    else:
        # Regular mode, just visualize the data
        show_interactive_plots(sample_df, data_type=data_type)
