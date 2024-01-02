import subprocess
import concurrent.futures

# Function to run nslookup for different record types
def run_nslookup(domain):
    record_types = ['A', 'MX', 'TXT', 'PTR']
    results = {}
    for record_type in record_types:
        try:
            print(f"Running nslookup for {record_type} record...")
            result = subprocess.check_output(['nslookup', '-type={}'.format(record_type), domain], encoding='utf-8')
            results[record_type] = result
        except subprocess.CalledProcessError as e:
            results[record_type] = e.output
    return results

# Function to run nmap scan
def run_nmap(domain):
    try:
        print("Running nmap full port TCP scan...")
        tcp_scan = subprocess.check_output(['nmap', '-sS', '-p-', '-sV', domain , '-oA', domain], encoding='utf-8')
        #print("Running nmap full port UDP scan...")
        #udp_scan = subprocess.check_output(['nmap', '-sU', '-p-', domain], encoding='utf-8')
        return tcp_scan #+ '\n' + udp_scan
    except subprocess.CalledProcessError as e:
        return e.output

# Function to extract open web service ports from nmap scan
#def extract_ports(nmap_results):
    lines = nmap_results.splitlines()
    ports = []
    for line in lines:
        if 'open' in line and 'http' in line:
            port = line.split('/')[0].strip()
            ports.append(port)
    return ports

def extract_ports(nmap_results):
    lines = nmap_results.splitlines()
    web_ports = [80, 443]  # Add more ports if needed
    open_ports = []

    for line in lines:
        if 'open' in line:
            port = line.split('/')[0].strip()
            service = line.split()[2].lower()  # Extract service name and convert to lowercase

            if int(port) in web_ports or 'http' in service:
                open_ports.append(port)

    return open_ports


# Function to run gobuster on given URL and port

#def run_gobuster(url, port):
    # Determine the protocol based on the port
    protocol = 'https' if port == '443' else 'http'
  
    try:
        print(f"Running gobuster on {protocol}://{url}:{port}/...")
        result = subprocess.check_output(
            ['gobuster', 'dir', '-u', f'{protocol}://{url}:{port}/', '-w', 'directory-list-2.3-medium.txt', '-k'], 
            encoding='utf-8'
        )
        return result
    except subprocess.CalledProcessError as e:
        return e.output

#def run_gobuster(url, port):
    # Determine the protocol based on the port
    protocol = 'https' if port == '443' else 'http'
  
    try:
        print(f"Running gobuster on {protocol}://{url}/...")
        result = subprocess.check_output(
            ['gobuster', 'dir', '-u', f'{protocol}://{url}/', '-w', 'directory-list-2.3-medium.txt','-k'], 
            encoding='utf-8'
        )
        return result
    except subprocess.CalledProcessError as e:
        return e.output
def run_gobuster(url, port):
    # Determine the protocol based on the port
    protocol = 'https' if port == '443' else 'http'
  
    try:
        print(f"Running gobuster on {protocol}://{url}/...")
        result = subprocess.check_output(
            ['gobuster', 'dir', '-u', f'{protocol}://{url}/', '-w', 'directory-list-2.3-medium.txt','-k'], 
            encoding='utf-8'
        )
        return result
    except subprocess.CalledProcessError as e:
        print(f"Error running gobuster on {protocol}://{url}:{port}/. Trying without port...")
        try:
            result = subprocess.check_output(
                ['gobuster', 'dir', '-u', f'{protocol}://{url}/', '-w', 'directory-list-2.3-medium.txt','-k'], 
                encoding='utf-8'
            )
            return result
        except subprocess.CalledProcessError as e:
            return e.output

# Function to run nikto on given URL and port
#def run_nikto(ip, ports):
    results = {}
    for port in ports:
        protocol = 'https' if port == '443' else 'http'
        try:
            print(f"Running nikto on {protocol}://{ip}:{port}...")
            result = subprocess.check_output(['nikto', '-h', f'{protocol}://{ip}:{port}'], encoding='utf-8')
            results[port] = result
        except subprocess.CalledProcessError as e:
            results[port] = e.output
    return results

#def run_nikto(ip, ports):
    results = {}
    for port in ports:
        protocol = 'https' if port == '443' else 'http'
        try:
            print(f"Running nikto on {protocol}://{ip}...")
            result = subprocess.check_output(['nikto', '-h', f'{protocol}://{ip}'], encoding='utf-8')
            results[port] = result
        except subprocess.CalledProcessError as e:
            results[port] = e.output
    return results

def run_nikto(ip, ports):
    results = {}
    for port in ports:
        protocol = 'https' if port == '443' else 'http'
        try:
            print(f"Running nikto on {protocol}://{ip}:{port}/...")
            result = subprocess.check_output(['nikto', '-h', f'{protocol}://{ip}:{port}/'], encoding='utf-8')
            results[port] = result
        except subprocess.CalledProcessError as e:
            print(f"Error running nikto on {protocol}://{ip}:{port}/. Trying without port...")
            try:
                result = subprocess.check_output(['nikto', '-h', f'{protocol}://{ip}/'], encoding='utf-8')
                results[port] = result
            except subprocess.CalledProcessError as e:
                results[port] = e.output
    return results

# Function that orchestrates the scanning for a single target
def scan_target(target, report_file):
    with open(report_file, 'a') as report:
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
        report.write('\n-----  Open Web Service ports  -----\n')
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

    print(f"Scan for target {target} completed.")

# Main function to run scans with multithreading
def main():
    # Read targets from file
    with open('targets.txt', 'r') as file:
        targets = file.read().splitlines()

    # Define the maximum number of threads
    # Be careful with this number - setting it too high may cause issues
    max_threads = 4
    
    # Initialize report file
    report_file = 'security_report.txt'
    open(report_file, 'w').close()  # Clear the report file
    
    # Use ThreadPoolExecutor to run scans in parallel
    with concurrent.futures.ThreadPoolExecutor(max_threads) as executor:
        # Map each target to a thread
        future_to_target = {executor.submit(scan_target, target, report_file): target for target in targets}
        
        for future in concurrent.futures.as_completed(future_to_target):
            target = future_to_target[future]
            try:
                data = future.result()
            except Exception as exc:
                print('%r generated an exception: %s' % (target, exc))
    
    print("\nAll scans have been completed and results are saved in 'security_report.txt'.")

if __name__ == '__main__':
    main()
