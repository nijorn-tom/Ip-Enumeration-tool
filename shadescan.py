import scapy.all as scapy
import nmap
import argparse
import ipaddress

def port_scan(ip, ports):
    """
    Scan for open ports on the target IP.
    """
    open_ports = []
    for port in ports:
        try:
            port = int(port)
            packet = scapy.TCP(dport=port, flags="S")
            packet_ip = scapy.IP(dst=ip)
            packet_ip_packet = packet_ip/packet
            response = scapy.sr1(packet_ip_packet, verbose=0, timeout=1)
            
            if response is not None:
                if response.haslayer(scapy.TCP):
                    if response.getlayer(scapy.TCP).flags == 0x12:
                        open_ports.append(port)
                        print(f"Port {port} is open")
        except ValueError:
            print(f"Invalid port: {port}")
    
    return open_ports

def service_scan(ip, open_ports):
    """
    Identify the services running on the open ports.
    """
    nm = nmap.PortScanner()
    nm.scan(ip, f"{min(open_ports)}-{max(open_ports)}")
    
    for port in open_ports:
        if nm[ip].tcp[port]['state'] == 'open':
            print(f"Service on port {port}: {nm[ip].tcp[port]['name']}")

def os_detection(ip):
    """
    Attempt to detect the operating system of the target IP.
    """
    nm = nmap.PortScanner()
    nm.scan(ip)
    print(f"Detected OS: {nm[ip].osmatch()[0].name()}")

def enum_tool(ip_range, ports):
    """
    Perform enumeration on the target IP range.
    """
    for ip in ipaddress.ip_network(ip_range).hosts():
        ip = str(ip)
        print(f"Enumerating {ip}...")
        
        if ports == ['-']:
            ports = range(1, 65536)
        
        open_ports = port_scan(ip, ports)
        service_scan(ip, open_ports)
        os_detection(ip)
        print()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Enumeration Tool")
    parser.add_argument("-r", "--range", help="Target IP range", required=True)
    parser.add_argument("-p", "--ports", help="Ports to scan", nargs="+", required=False)
    args = parser.parse_args()
    
    ip_range = args.range
    ports = args.ports
    
    if ports:
        if ports[0] == '-':
            ports = ['-']
        else:
            ports = ports
    else:
        ports = []
    
    enum_tool(ip_range, ports)

