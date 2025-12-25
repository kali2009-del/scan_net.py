import nmap
def nmap_port_scanner(target_ip, port_range):
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=target_ip, ports=port_range)
        for host in nm.all_hosts():
            print(f"Host : {host} ({nm[host].hostname()})")
            print(f"State : {nm[host].state()}")
            for proto in nm[host].all_protocols():
                print(f"----------")
                print(f"Protocol : {proto}")
                lport = nm[host][proto].keys()
                for port in sorted(lport):
                    state = nm[host][proto][port]['state']
                    service = nm[host][proto][port]['name']
                    print(f"Port : {port}\tState : {state}\tService : {service}")
    except nmap.nmap.PortScannerError as e:
        print(f"An error occurred during the scan: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
def main():
    target_ip = input("Please enter target IP address to scan: ")
    port_range = input("Please enter the port range (e.g., '21-443'): ")
    print(f"\nStarting Nmap scan on {target_ip} for ports {port_range}...")
    nmap_port_scanner(target_ip, port_range)
main()
