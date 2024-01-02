import os
import subprocess

# Function to run nslookup for different record types
def run_nslookup(domain):
    record_types = ['A', 'MX', 'TXT', 'PTR']
    results = {}
    for record_type in record_types:
        try:
            result = subprocess.check_output(['nslookup', '-type={}'.format(record_type), domain], encoding='utf-8')
            results[record_type] = result
        except subprocess.CalledProcessError as e:
            results[record_type] = e.output
    return results

# Function to run nmap scan
def run_nmap(domain):
    try:
        tcp_scan = subprocess.check_output(['nmap', '-sS', '-p-', '-sV', domain], encoding='utf-8')
        udp_scan = subprocess.check_output(['nmap', '-sU', '-p-', domain], encoding='utf-8')
        return tcp_scan + '\n' + udp_scan
    except subprocess.CalledProcessError as e:
        return e.output

# Function to extract open web service ports from nmap scan
def extract_ports(nmap_results):
    lines = nmap_results.splitlines()
    ports = []
    for line in lines:
        if 'open' in line and 'http' in line:
            port = line.split('/')[0].strip()
            ports.append(port)
    return ports

# Function to run gobuster on given URL and port
def run_gobuster(url, port):
    try:
        result = subprocess.check_output(['gobuster', 'dir', '-u', f'{url}:{port}', '-w', 'directory-list-2.3-medium.txt'], encoding='utf-8')
        return result
    except subprocess.CalledProcessError as e:
        return e.output

# Function to run nikto on given URL and port
def run_nikto(ip, ports):
    results = {}
    for port in ports:
        try:
            result = subprocess.check_output(['nikto', '-h', f'{ip}' if port == '80' else f'{ip}:{port}'], encoding='utf-8')
            results[port] = result
        except subprocess.CalledProcessError as e:
            results[port] = e.output
    return results

# Main function to run scans
def main():
    # Read targets from file
    with open('targets.txt', 'r') as file:
        targets = file.read().splitlines()
    
    # Create a new report file
    report_file = 'security_report.txt'
    with open(report_file, 'w') as report:
        for target in targets:
            report.write(f'\n-----  Target IP: {target}  -----\n')
            # Run nslookup
            ns_results = run_nslookup(target)
            for record_type, result in ns_results.items():
                report.write(f'\n-----  NSLOOKUP {record_type} Record  -----\n')
                report.write(result)
            
            # Run Nmap scan
            nmap_results = run_nmap(target)
            report.write('\n-----  NMAP Scan Results  -----\n')
            report.write(nmap_results)
            
            # Extract open web service ports
            ports = extract_ports(nmap_results)
            
            # Run Gobuster on open web ports
            for port in ports:
                gobuster_result = run_gobuster(target, port)
                report.write(f'\n-----  Gobuster Scan Result for Port {port}  -----\n')
                report.write(gobuster_result)
            
            # Run Nikto on open web ports
            nikto_results = run_nikto(target, ports)
            for port, result in nikto_results.items():
                report.write(f'\n-----  Nikto Scan Result for Port {port}  -----\n')
                report.write(result)

if __name__ == '__main__':
    main()
