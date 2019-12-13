import ipaddress
from typing import Optional, Text, Tuple


def hash_f(x: Text) -> Tuple[Text, Text]:
    return "hash", x.lower()


def certificate_f(x: Text) -> Tuple[Text, Text]:
    return "certificate", x.lower()


def threat_actor_f(x: Text) -> Tuple[Text, Text]:
    return "threatActor", x.lower()


def campaign_f(x: Text) -> Tuple[Text, Text]:
    return "campaign", x.lower()


def email_f(x: Text) -> Tuple[Text, Text]:
    return "uri", "email://{}".format(x.lower())


def person_f(x: Text) -> Tuple[Text, Text]:
    return "person", x.lower()


def organization_f(x: Text) -> Tuple[Text, Text]:
    return "organization", x.lower()


def fqdn_f(x: Text) -> Tuple[Text, Text]:
    return "fqdn", x.lower()


def ipv4net_f(x: Text) -> Tuple[Text, Text]:
    return "ipv4Network", x.lower()


def tools_f(x: Text) -> Tuple[Text, Text]:
    return "tools", x.lower()


def ip_f(x: Text) -> Tuple[Optional[Text], Optional[Text]]:
    try:
        addrv6 = ipaddress.IPv6Address(x)
        return "ipv6", str(addrv6.exploded)
    except ipaddress.AddressValueError:
        try:
            ipaddress.IPv4Address(x)
            return "ipv4", x
        except ipaddress.AddressValueError:
            pass

    return None, None


def uri_f(x: Text) -> Tuple[Text, Text]:
    if not x.startswith("http"):
        x = "http://{0}".format(x)
    return "uri", x


def user_agent_f(x: Text) -> Tuple[Text, Text]:
    return "userAgent", x


def vulnerability_f(x: Text) -> Tuple[Text, Text]:
    return "vulnerability", x.lower()


def mutex_f(x: Text) -> Tuple[Text, Text]:
    return "mutex", x
