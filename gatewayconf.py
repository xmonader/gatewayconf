"""
This module assume having tcprouter and coredns installed.
tfgateway = TFGateway() # or another redisclient
tfgateway.tcpservice_register("bing", "www.bing.com", "122.124.214.21")
tfgateway.domain_register_a("ahmed", "bots.grid.tf.", "123.3.23.54")
"""
import json
import base64
import ipaddress
from redis import Redis

base64encode = base64.b64encode


def ip_check(ip):
    """
    checks if ip is valid ip4 or ip6 or not
    """
    try:
        ipaddress.IPv4Address(ip)
    except:
        try:
            ipaddress.IPv6Address(ip)
        except:
            return False
        else:
            return True
    else:
        return True


class TFGateway:
    """
    tool to register tcpservices in tcprouter and coredns records
    """

    def __init__(self, redisclient=None, **kwargs):
        self.redisclient = redisclient or Redis(**kwargs)

    def _records_get(self, record_ip):
        records = []
        if isinstance(record_ip, str):
            ip_check(record_ip)
            records = [{"ip": record_ip}]

        elif isinstance(record_ip, list):
            for ip in record_ip:
                ip_check(ip)
                records.append({"ip": ip})
        return records

    ## COREDNS redis backend
    def domain_register(self, name, domain="bots.grid.tf.", record_type="a", records=None):
        """registers domain in coredns (needs to be authoritative)

        e.g: ahmed.bots.grid.tf

        requires nameserver on bots.grid.tf (authoritative)
        - ahmed is name
        - domain is bots.grid.tf

        :param name: name
        :type name: str
        :param domain: str, defaults to "bots.grid.tf."
        :type domain: str, optional
        :param record_type: valid dns record (a, aaaa, txt, srv..), defaults to "a"
        :type record_type: str, optional
        :param records: records list, defaults to None
        :type records: [type], optional is [ {"ip":machine ip}] in case of a/aaaa records
        """
        if not domain.endswith("."):
            domain += "."
        data = {}
        records = records or []
        if self.redisclient.hexists(domain, name):
            data = json.loads(self.redisclient.hget(domain, name))

        if record_type in data:
            for record in data[record_type]:
                if record not in records:
                    records.append(record)
        data[record_type] = records
        self.redisclient.hset(domain, name, json.dumps(data))

    def domain_list(self):
        return self.redisclient.keys("*.")

    def domain_exists(self, domain):
        if not domain.endswith("."):
            domain += "."
        if self.redisclient.exists(domain):
            return True
        subdomain, domain = domain.split(".", 1)
        return self.redisclient.hexists(domain, subdomain)

    def domain_dump(self, domain):
        if not domain.endswith("."):
            domain += "."
        resulset = {}
        for key, value in self.redisclient.hgetall(domain).items():
            resulset[key.decode()] = json.loads(value)
        return resulset

    def subdomain_get(self, domain, subdomain):
        if not domain.endswith("."):
            domain += "."
        subdomain_info = self.redisclient.hget(domain, subdomain)
        return json.loads(subdomain_info)

    def domain_register_a(self, name, domain, record_ip):
        """registers A domain in coredns (needs to be authoritative)

        e.g: ahmed.bots.grid.tf

        requires nameserver on bots.grid.tf (authoritative)
        - ahmed is name
        - domain is bots.grid.tf

        :param name: myhost
        :type name: str
        :param domain: str, defaults to "grid.tf."
        :type domain: str, optional
        :param record_ip: machine ip in ipv4 format
        :type record_ip: str or list of str
        """
        records = self._records_get(record_ip)
        return self.domain_register(name, domain, record_type="a", records=records)

    def domain_register_aaaa(self, name, domain, record_ip):
        """registers A domain in coredns (needs to be authoritative)

        e.g: ahmed.bots.grid.tf

        requires nameserver on bots.grid.tf (authoritative)
        - ahmed is name
        - domain is bots.grid.tf

        :param name: name
        :type name: str
        :param domain: str, defaults to "bots.grid.tf."
        :type domain: str, optional
        :param record_ip: machine ips in ipv6 format
        :type record_ip: list of str
        """
        records = self._records_get(record_ip)
        return self.domain_register(name, domain, record_type="aaaa", records=records)

    def domain_register_cname(self, name, domain, host):
        """Register CNAME record

        :param name: name
        :type name: str
        :param domain: str, defaults to "bots.grid.tf."
        :type domain: str, optional
        :param host: cname
        :type host: str
        """
        if not host.endswith("."):
            host += "."
        self.domain_register(name, domain, "cname", records=[{"host": host}])

    def domain_register_ns(self, name, domain, host):
        """register NS record

        :param name: name
        :type name: str
        :param domain: str, defaults to "bots.grid.tf."
        :type domain: str, optional
        :param host: host
        :type host: str

        """
        self.domain_register(name, domain, "ns", records=[{"host": host}])

    def domain_register_txt(self, name, domain, text):
        """register TXT record

        :param name: name
        :type name: str
        :param domain: str, defaults to "bots.grid.tf."
        :type domain: str, optional
        :param text: text
        :type text: text
        """

        self.domain_register(name, domain, "txt", records=[{"text": text}])

    def domain_register_mx(self, name, domain, host, priority=10):
        """register MX record

        :param name: name
        :type name: str
        :param domain: str, defaults to "bots.grid.tf."
        :type domain: str, optional
        :param host: host for mx e.g mx1.example.com
        :type host: str
        :param priority: priority defaults to 10
        :type priority: int

        """

        self.domain_register(name, domain, "mx", records=[{"host": host, "priority": priority}])

    def domain_register_srv(self, name, domain, host, port, priority=10, weight=100):
        """register SRV record

        :param name: name
        :type name: str
        :param domain: str, defaults to "bots.grid.tf."
        :type domain: str, optional
        :param host: host for mx e.g mx1.example.com
        :type host: str
        :param port: port for srv record
        :type port: int
        :param priority: priority defaults to 10
        :type priority: int
        :param weight: weight defaults to 100
        :type weight: int

        """
        self.domain_register(
            name, domain, "srv", records=[{"host": host, "port": port, "priority": priority, "weight": weight}]
        )

    ## TCP Router redis backend
    def tcpservice_register(self, domain, service_addr="", service_port=443, service_http_port=80, client_secret=""):
        """
        register a tcpservice to be used by tcprouter in j.core.db

        :param domain: (Server Name Indicator SNI) (e.g www.facebook.com)
        :type domain: str
        :param service_addr: IPAddress of the service
        :type service_endpoint: string
        :param service_port: Port of the tls services
        :type service_port: int
        :param service_http_port: Port of the service
        :type service_http_port: int
        """
        if not any([service_addr, client_secret]) or all([service_addr, client_secret]):
            raise ValueError(
                f"Need to provide only service_addr (you passed {service_addr}) or client_secret (you passed {client_secret})"
            )
        service = {}
        service["Key"] = "/tcprouter/service/{}".format(domain)
        record = {
            "addr": service_addr,
            "tlsport": service_port,
            "httpport": service_http_port,
            "clientsecret": client_secret,
        }
        json_dumped_record_bytes = json.dumps(record).encode()
        b64_record = base64encode(json_dumped_record_bytes).decode()
        service["Value"] = b64_record
        self.redisclient.set(service["Key"], json.dumps(service))


def local_redis_gateway():
    return TFGateway()
