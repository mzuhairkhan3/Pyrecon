import socket
import threading
import queue
from concurrent.futures import ThreadPoolExecutor, as_completed
from scanner.fingerprint import get_service_name, identify_software, get_probe

def scan_port(host: str, port: int, timeout: float=1.0) -> dict:
    """
    Attempt a TCP connection to host:port.
     Returns a dict with port, status and error info
    """

    result={
        "port":port,
        "status":"closed",
        "error":None,
    }

    try:
        # AF_INET =IPv4
        # SOCK_STREAM = TCP (as opposed to UDP which is SOCK_DGRAM)
        sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # if no response in timeout seconds, give up on this port
        sock.settimeout(timeout)

        #connect_ex returns 0 on success, errno code on failure
        # we use connect_ex instead of connect() because connect()
        #rasies an exception on failure which is harder to handle in a loop
        code=sock.connect_ex((host, port))

        if code==0:
            result["status"]="open"
        else:
            result["status"]="closed"
            result["error"]=code
        
    except socket.gaierror as e:
        #getaddrinfo error, host doesnt resolve
        result["status"]="error"
        result["error"]=str(e)

    finally:
        #always close the socket, even if something went wrong
        sock.close()

    return result


def resolve_host(host: str) -> str:
    """
    Resolve a hostname to an IP adddress.
    Raises socket.gaierror if it fails.
    """

    return socket.gethostbyname(host)


def parse_port_range(port_str: str) -> list[int]:
    """
    Parse a port string into a lst of ints.
    Accepts:
    "80" -> [80]
    "1-1024" -> [1,2,3,...,1024]
    "22,80,443" -> [22,80,443]
    """
    ports=[]
    if "-" in port_str:
        start, end=port_str.split("-")
        ports=list(range(int (start), int(end)+1))
    elif "," in port_str:
        ports=[int(p.strip()) for p in port_str.split(",")]
    else:
        ports=[int(port_str)]

    #Validate range: ports must be 1-65535
    for p in ports:
        if not (1<=p<=65535):
            raise ValueError(f"Port {p} is out of range")
        
    return ports


def scan_range(host: str, ports: list[int], timeout: float=1.0) -> list[dict]:
    """
    Scan a list of ports sequentially.
    Returns a list of result dicts, one per port.
    """
    results=[]

    for port in ports:
        result=scan_port(host,port,timeout)
        results.append(result)

    return results

print_lock=threading.Lock()

def _scan_worker(host: str, port: int, timeout: float, result_queue: queue.Queue, callback=None):
    """
    Worker function runs inside a thread
    Scans one port enriches if open
    """

    result=scan_port(host, port, timeout)
    if result["status"]=="open":
        result=enrich_result(result, host, timeout)
        
    result_queue.put(result)

    #callback lets the caller react to each result live, e.g. print it
    # Must be thread safe:  caller's responsiblity to use print lock

    if callback:
        callback(result)

    
def threaded_scan(host: str, ports: list[int], timeout: float=1.0, max_threads: int=100, callback=None) -> list[dict]:
    """
    scan ports concurrently using a thread pool.
    
    host: resolved IP address
    ports: list of port ints to scan
    timeout: per port socket timeout
    max_threads: max concurrent threads (default 100)
    callback: optional functio called with each result as it arrives
    """

    result_queue=queue.Queue()
    results=[]

    #ThreadPoolExecutor manages a pool of worker threads.
    #max_workers caps how many run simultaneously.

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        #submit one task per port executor will queue the internally

        futures=[
            executor.submit(
                _scan_worker, host, port, timeout, result_queue, callback
            )
            for port in ports
        ]


        # as_completed() yields each future the moment it finishes
        # This is where we block until all threads are done


        for future in as_completed(futures):
            # Catch any exception a worker thread threw
            # Without this, thread exceptions die silently
            try:
                future.result()
            except Exception as e:
                with print_lock:
                    print(f" [Thread error] {e}")

    #drain the queue into a list
    while not result_queue.empty():
        results.append(result_queue.get())

    #sort by port number: treaded results arrive out of order
    results.sort(key=lambda r: r["port"])
    return results


def grab_banner(host: str, port: int, timeout: float=2.0) -> str:
    """
    Connect to an open port and attempt to read its banner.
    Sends a probe if the service wont speak first
    Returns the raw banner string, or empty string on failure
    """

    banner=""
    try:
        sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        probe=get_probe(port)

        if probe is not None:
            sock.sendall(probe)

        raw=sock.recv(1024)
        banner=raw.decode("utf-8", errors="ignore").strip()
    except (socket.timeout, socket.error, ConnectionRefusedError):
        banner=""
    finally:
        sock.close()
    return banner


def enrich_result(result:dict, host: str, timeout: float=2.0) -> dict:
    """
    Take an open port result and add banner + fingerprint data
    Only call this on ports with status=="open"
    """

    port=result["port"]
    banner=grab_banner(host, port, timeout)

    result["service"]=get_service_name(port)
    result["banner"]=banner
    result["software"]=identify_software(banner)

    return result


