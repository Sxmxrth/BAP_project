import pandas as pd
import nmap
from tqdm import tqdm
from datetime import datetime
import os

def run_nmap(ip_subnet):
    # Initialize the Nmap scanner
    nm = nmap.PortScanner()

    # Get the number of hosts to estimate progress
    nm.scan(hosts=ip_subnet, arguments='-sn')  # Quick ping scan to get hosts
    total_hosts = len(nm.all_hosts())

    # Process the scan results and store them in a DataFrame
    data = []
    timestamp = datetime.now()  # Timestamp for the scan

    with tqdm(total=total_hosts, desc="Scanning hosts") as pbar:
        for host in nm.all_hosts():
            try:
                # Run the Nmap scan for each host
                nm.scan(hosts=host, arguments='-sS -A')

                # Get all the information received for the host
                host_info = nm[host]
                open_ports = [port for port in host_info['tcp'].keys() if host_info['tcp'][port]['state'] == 'open']
                
                # Extract service information
                services = []
                for port in open_ports:
                    service_name = host_info['tcp'][port].get('name', 'Unknown')
                    service_protocol = host_info['tcp'][port].get('product', 'Unknown')
                    services.append(f"{service_name}/{service_protocol}")

                host_data = {
                    'IP': host,
                    'Status': host_info['status']['state'],
                    'Hostname': host_info['hostnames'][0]['name'] if host_info['hostnames'] else '',
                    'MAC Address': host_info['addresses']['mac'] if 'mac' in host_info['addresses'] else '',
                    'Vendor': host_info['vendor'][host_info['addresses']['mac']] if 'mac' in host_info['addresses'] and host_info['vendor'] else 'Unknown',
                    'OS': host_info['osmatch'][0]['name'] if host_info['osmatch'] else '',
                    'Open Ports': ' '.join(map(str, open_ports)),
                    'Services': ' '.join(services) if services else 'No services detected',
                    'Timestamp': timestamp,
                    # Add more fields as needed
                }
                print(host_data)
                data.append(host_data)
            except KeyError as e:
                print(f"Error processing host {host}: {e}")
            pbar.update(1)  # Update progress bar

    df = pd.DataFrame(data)
    return df

def export_to_csv(df, filename):
    # Check if the file already exists
    file_exists = os.path.isfile(filename)
    
    # Export the DataFrame to a CSV file
    if not file_exists:
        df.to_csv(filename, index=False)
    else:
        df.to_csv(filename, mode='a', header=False, index=False)


def main():
    # Get the IP subnet from the user
    ip_subnet = input("Enter the IP subnet (e.g., 192.168.1.0/24): ")

    # Run Nmap scan and store results in a DataFrame
    df = run_nmap(ip_subnet)

    # Export DataFrame to CSV
    filename = "nmap_results.csv"
    export_to_csv(df, filename)

if __name__ == "__main__":
    main()
