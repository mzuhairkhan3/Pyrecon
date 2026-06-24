#service name map
#maps port number to service name
SERVICE_MAP={
    20:"FTP-data", 21: "FTP", 22: "SSH",
    23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DGCP", 68: "DHCP", 69: "TFTP",
    80: "HTTP", 110: "POP3", 111: "RPCblind",
    119: "NNTP", 123: "NTP", 135: "MSRPC",
    139: "NetBIOS", 143: "IMAP", 161: "SNMP",
    194: "IRC", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 514: "Syslog", 515: "LPD",
    587: "SMTP-sub", 631: "IPP", 993:  "IMAPS",
    995: "POP3S", 1080:"SOCKS", 1433: "MSSQL",
    1521: "Oracle-DB", 2049:"NFS", 3306: "MySQL",
    3389: "RDP", 4444:"Metasploit", 5432: "PostgreSQL",
    5900: "VNC", 6379:"Redis", 6667: "IRC",
    8080: "HTTP-alt", 8443:"HTTPS-alt", 8888: "HTTP-alt",
    9200: "Elasticsearch", 27017:"MongoDB",
}


# software signature map
#maps banner substrings to idetified software name
#checked in order: put more specific signatures first
SIGNATURES=[
    #SSH
    ("OpenSSH", "OpenSSH"),
    ("Dropbear", "Dropbear SSH"),
    ("SSH-2.0-libssh", "libssh"),

    #web servers
    ("Apache", "Apache httpd"),
    ("nginx", "nginx"),
    ("Microsoft-IIS", "Microsoft IIS"),
    ("lighttpd", "lighttpd"),
    ("gunicorn", "Gunicorn"),
    ("cloudflare", "Cloudflare"),

    #mail
    ("Postfix", "Postfix SMTP"),
    ("Exim", "Exim SMTP"),
    ("Dovecot", "Dovecot"),
    ("Sendmail", "Sendmail"),
    ("Microsoft Exchange", "Microsoft Exchange"),

    #FTP
    ("vsftpd", "vsftpd"),
    ("ProFTPD", "ProFTPD"),
    ("FileZilla", "FileZilla FTP"),

    #Databases
    ("MySQL","MySQL"),
    ("MariaDB", "MariaDB"),
    ("PostgreSQL", "PostgreSQL"),
    ("redis_version", "Redis"),
    ("MongoDB", "MongoDB"),

    #other
    ("Telnet", "Telnet"),
    ("VNC", "VNC"),
    ("RDP", "RDP"),
    ("220", "FTP/SMTP service"),   # generic 220 greeting
]

#probe map
#maps probe number to bytes to send as a probe
PROBES={
    80: b"HEAD / HTTP/1.0\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\n\r\n",
    8888: b"HEAD / HTTP/1.0\r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\n\r\n",
    443:  b"HEAD / HTTP/1.0\r\n\r\n",
    21: None, #FTP speaks first
    22: None,  #SSH speaks first
    25: None, #SMTP speaks first
    110: None, #POP3 speaks first
    143: None, #IMAP speaks first
}


DEFAULT_PROBE= b"\r\n"

def get_service_name(port: int) -> str:
    """
    Return known service name for port or unknown
    """
    return SERVICE_MAP.get(port, "Unknown")


def identify_software(banner: str) -> str:
    """Match banner text against known signatures.
    Returns software name or empty string if no match.
    """
    
    banner_lower=banner.lower()
    for substring, name in SIGNATURES:
        if substring.lower() in banner_lower:
            return name
    return ""


def get_probe(port: int) -> bytes:
    # return the probe bytes for a given port
    if port in PROBES:
        return PROBES[port]
    return DEFAULT_PROBE