import argparse
import socket
import time
from colorama import Fore, Style, init
from scanner.tcp import (scan_port, threaded_scan, parse_port_range, resolve_host, print_lock)
from scanner.report import get_host_info, build_report, save_report
init(autoreset=True) # reset color after each print

def print_banner(host_info: dict, ports: list[int], threads: int):
    ip=host_info["ip"]
    target=host_info["input_host"]
    reverse_dns=host_info["reverse_dns"]
    scan_time=host_info["scan_time"]

    print(f"\n{'-'*45}")
    print(f" Pyrecon: TCP Port Scanner")
    print(f"{'-'*45}")
    print(f" Target : {target} ({ip})")
    print(f"IP : {ip}")
    print(f"Reverse DNS : {reverse_dns}")
    print(f"Scan time : {scan_time}")
    print(f" Ports : {ports[0]}-{ports[-1]}  ({len(ports)} ports)")
    print(f" Threads : {threads}")
    print(f"{'-'*45}\n")

def live_callback(result: dict):
    """
    Live print as each open port is discovered
    """
    if result["status"]=="open":
            port=result["port"]
            service=result.get("service", "unknown")
            software=result.get("software", "")
            banner=result.get("banner", "")

            #truncate long banners fpr live display

            banner_preview=banner[:55].replace("\n"," ") if banner else ""
            software_str=f"({software})" if software else ""

            with print_lock:
                print(f" {Fore.GREEN}[OPEN] {Style.RESET_ALL} "
                    f"{port:<6} {Fore.GREEN}{service}{software_str}{Style.RESET_ALL}" )
                if banner_preview:
                    print(f" {' '*8} {Fore.CYAN}↳ {banner_preview}{Style.RESET_ALL}")



def print_summary(results: list[dict], elapsed: float):
    open_ports=[r for r in results if r["status"]=="open"]
    closed_ports=[r for r in results if r["status"]=="closed"]
    error_ports=[r for r in results if r["status"]=="error"]

    print(f"\n{'-'*55}")
    print(f"scan complete in {elapsed:.2f}s")
    print(f"  {Fore.GREEN}{len(open_ports)} open{Style.RESET_ALL}   "
        f"{Fore.RED}{len(closed_ports)} closed{Style.RESET_ALL}   "
        f"{Fore.YELLOW}{len(error_ports)} errors{Style.RESET_ALL}")
    print(f"{'-'*55}")

    if open_ports:
        print(f"\n {'PORT':<8} {'SERVICE':<14} {'SOFTWARE' :<22} BANNER")
        print(f" {'-'*70}")
        for r in open_ports:
            port=r["port"]
            service=r.get("service", "unknown")
            software=r.get("software","-")
            banner=r.get("banner", "")
            banner_s=banner[:32].replace("\n", " ") if banner else "—"
            print(f" {Fore.GREEN}{port:<8}{Style.RESET_ALL} "
                  f"{service:<14}"
                  f"{software:<22}"
                  f"{Fore.CYAN}{banner_s}{Style.RESET_ALL}")
    else:
        print(f"\n {Fore.YELLOW}No open ports found.{Style.RESET_ALL}")
    print()

def main():
    parser=argparse.ArgumentParser(
        description="Pyrecon: a port scanner built from scratch",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-t", "--target", required=True, help="Target host or IP address")
    parser.add_argument("-p", "--ports", required=True, help="Ports to scan: range(1-1024), list(22,80,443) or single(80)")
    parser.add_argument("--threads", type=int, default=100, help="Concurrent threads (default 100)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Timeout per port in seconds (default: 1.0)")
    parser.add_argument("--output", type=str, default=None, help="Save report to file (e.g. --output report.txt)")
    parser.add_argument("--no-threads", action="store_true", help="Disable threading, run sequentially")
    args=parser.parse_args()

    #Step 1: resolve the hostname
    try:
        ip=resolve_host(args.target)
    except socket.gaierror:
        print(f"{Fore.RED}Error: Unable to resolve host '{args.target}'{Style.RESET_ALL}\n")
        return
    
    #Step 2: parse ports
    try:
        ports=parse_port_range(args.ports)
    except ValueError as e:
        print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}\n")
        return
    
    #Step 3: collect host metadata
    host_info=get_host_info(args.target, ip)

    #Step 4: print banner
    threads= 1 if args.no_threads else args.threads
    print_banner(host_info, ports, threads)

    #Step 4: scan
    start=time.time()
    if args.no_threads:
        results=[]
        for port in ports:
            result=scan_port(ip, port, args.timeout)
            results.append(result)
            if result["status"]=="open":
                live_callback(result) # prints only if open
    else:
        #threaded path
        results=threaded_scan(
            host=ip,
            ports=ports,
            timeout=args.timeout,
            max_threads=args.threads,
            callback=live_callback
        )    
    elapsed=time.time()-start

    # Step 6: terminal summary
    print_summary(results, elapsed)

    # Step 7: save report
    if args.output:
        report_str=build_report(host_info, results, elapsed)
        save_report(report_str, args.output)
        print(f" {Fore.GREEN}Report Saved! {args.output}{Style.RESET_ALL}\n")

if __name__=="__main__":
    main()