import socket
from datetime import datetime

def get_host_info(host: str, ip: str) -> dict:
    """
    Collect metadata bot the target before scanning
    Attempts a reverse DNS lookup on the IP
    """

    try:
        reverse_dns=socket.gethostbyaddr(ip)[0]
    except socket.herror:
        reverse_dns="N/A"

    return {
        "input_host": host,
        "ip": ip,
        "reverse_dns": reverse_dns,
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


def build_report(host_info: dict, results: list[dict], elapsed: float) -> str:
    """
    Build a plaintext report string from scan results 
    Returns the full report as a string and caller decides where it goes
    """
    open_ports=[r for r in results if r["status"]=="open"]
    closed_ports=[r for r in results if r["status"]=="closed"]
    error_ports=[r for r in results if r["status"]=="error"]
    lines=[]
    sep="="*60
    thin="-"*60

    #header
    lines += [
        sep,
        "Pyrecon: Port Scanner Report",
        sep,
        f"Target: {host_info['input_host']}",
        f"IP Address: {host_info['ip']}",
        f"Reverse DNS: {host_info['reverse_dns']}",
        f"Scan Time: {host_info['scan_time']}",
        f"Duraration: {elapsed:.2f}s",
        sep,
        "",
    ]
    #summary
    lines += [
        "SUMMARY",
        thin,
        f"Open ports: {len(open_ports)}",
        f"Closed ports: {len(closed_ports)}",
        f"Error ports: {len(error_ports)}",
        "",
    ]
    #open port table
    if open_ports:
        lines += [
            "OPEN PORTS",
            thin,
            f"{'PORT':<8} {'SERVICE':<16} {'SOFTWARE':<24} BANNER",
            f" {'-'*70}",
        ]
        for r in open_ports:
            port=str(r["port"])
            service=r.get("service", "unknown")
            software=r.get("software", "-")
            banner=r.get("banner", "").replace("\n"," ").replace("\r","")
            banner_s=banner[:40] if banner else "-"

            lines.append(
                f" {port:<8} {service:<16} {software:<24} {banner_s}"
            )

        # full banner section untruncated
        lines += ["FULL BANNERS",thin]
        for r in open_ports:
            banner=r.get("banner", "").strip()
            if banner:
                lines += [
                    f"Port {r['port']} ({r.get('service','unknown')}):",
                    f"{banner}",
                    "",
                ]
            else:
                lines.append(f"Port {r['port']}: no banner recieved\n")
    else:
        lines += ["OPEN PORTS", thin, "No open ports found."]
    
    #Footer
    lines += [sep,"End of report", sep, ""]
    return "\n".join(lines)

def save_report(report_str: str, filepath: str):
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(report_str)
    return filepath
    
