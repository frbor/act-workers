import enum
import uuid
import json
import time
import re

from typing import Optional, Text, Any, Tuple, Dict, Callable

from act.workers.libs import objmapper

class ThreatLevelID(enum.Enum):
    """2.2.1.5.  threat_level_id

    threat_level_id represents the threat level.

    4:   Undefined
    3:   Low
    2:   Medium
    1:   High

    If a higher granularity is required, a MISP taxonomy applied as a Tag
    SHOULD be preferred.

    threat_level_id SHALL be present."""

    HIGH = 1
    MEDIUM = 2
    LOW = 3
    UNDEFINED = 4


class Analysis(enum.Enum):
    """2.2.1.6.  analysis

    analysis represents the analysis level.

    0:   Initial
    1:   Ongoing
    2:   Complete

    If a higher granularity is required, a MISP taxonomy applied as a Tag
    SHOULD be preferred.

    analysis SHALL be present."""

    INITIAL = 0
    ONGOING = 1
    COMPLETE = 2


class Distribution(enum.Enum):
    """2.2.1.13.  distribution

    distribution represents the basic distribution rules of the event.  The
    system must adhere to the distribution setting for access control and for
    dissemination of the event.

    distribution MUST be present and be one of the following options:

    0 Your Organisation Only
    1 This Community Only
    2 Connected Communities
    3 All Communities
    4 Sharing Group"""

    ORGANIZATION_ONLY = 0
    COMMUNITY_ONLY = 1
    CONNECTED_COMMUNITIES = 2
    ALL_COMMUNITIES = 3
    SHARING_GROUP = 4
    INHERIT_EVENT = 5


class Event(object):

    # --- MUST ----
    _uuid = None
    published = None
    info = None
    threat_level_id = ThreatLevelID.UNDEFINED
    analysis = Analysis.INITIAL
    date = None  # ISO-8601 (date only: YYYY-MM-DD) reference date of the event
    timestamp = None  # Timestamp of event creation or event/attribute last update
    publish_timestamp = None  # reference time when the event was published on the instance.
    org_id = None  # Human readable org. generating the Event
    orgc_id = None  # Human readble org. *creating* the Event
    attribute_count = 0
    distribution = Distribution.ORGANIZATION_ONLY
    sharing_group_id = None
    # --- END_MUST ----

    # --- SHOULD ---
    extends_uuid = None
    # --- END_SHOULD ---

    tlp = None
    misp_galaxy: Dict[Text, Text] = {}

    def __init__(self, loads: Optional[Text]=None) -> None:
        self._uuid: uuid.UUID = uuid.uuid4()
        self.timestamp: int = int(time.time())
        self.publish_timestamp: int = int(time.time())

        if loads:
            data = json.loads(loads)
            event = data["Event"]
            self._uuid = uuid.UUID(event["uuid"])
            self.published = event["published"]
            self.info = event["info"]
            self.threat_level_id = ThreatLevelID(int(event["threat_level_id"]))
            self.analysis = Analysis(int(event["analysis"]))
            self.date = event["date"]
            self.timestamp = event["timestamp"]
            self.publish_timestamp = event["publish_timestamp"]
            self.org_id = event.get("org_id", "N/A")
            self.orgc_id = event.get("orgc_id", "N/A")
            self.attribute_count = event.get("attribute_count", 0)
            self.distribution = Distribution(int(event.get("distribution", 0)))
            self.sharing_group_id = event.get("sharing_group_id", None)
            self.extends_uuid = event.get("extends_uuid", None)

            misp_re = re.compile(r'misp-galaxy:(.*?)="(.*?)"')
            for tag in event.get("Tag", []):
                name = tag["name"]
                if name.startswith("tlp"):
                    self.tlp = name.split(":")[1]
                if name.startswith("misp-galaxy"):
                    for match in misp_re.findall(name):
                        self.misp_galaxy[match[0]] = match[1]

            self.attributes = [Attribute(e) for e in event.get("Attribute", [])]
            objects = event.get("Object", [])
            for obj in objects:
                obj_attributes = obj.get("Attribute", [])
                self.attributes += [Attribute(e) for e in obj_attributes]

    def __str__(self) -> Text:
        return "({0}) {1} - {2} ".format(self.timestamp, self._uuid, self.info)

    def write_to(self, stream: Any) -> None:
        stream.write(json.dumps(
            {
                "uuid": str(self._uuid),
                "published": self.published,
                "info": self.info,
                "threat_level_id": self.threat_level_id.value,
                "analysis": self.analysis.value,
                "date": self.date,
                "timestamp": self.timestamp,
                "publish_timestamp": self.publish_timestamp,
                "org_id": self.org_id,
                "orgc_id": self.orgc_id,
                "attribute_count": self.attribute_count,
                "distribution": self.distribution.value,
                "sharing_group_id": self.sharing_group_id,
                "extends_uuid": self.extends_uuid,
            }))

    @property
    def uuid(self):  # type: ignore
        return self._uuid


class Attribute(object):  # attributeattributes in misp babel

    def __init__(self, attributedict: Dict[Text, Text]):

        try:
            self._uuid = attributedict["uuid"]
            self.id: Text = attributedict["uuid"]
            mapper_fn = map_misp_to_act.get(attributedict["type"], lambda x: (None, None))
            self.act_type: Optional[Text] = None
            self.value: Optional[Text] = None
            self.act_type, self.value = mapper_fn(attributedict["value"])
            if "RelatedAttribute" in attributedict and attributedict["RelatedAttribute"]:
                print("DEBUG: {0}".format(attributedict["RelatedAttribute"]))
        except:
            print(attributedict)
            print(attributedict["value"][:100])
            raise

    def __str__(self) -> Text:
        return "{0} {1}:{2}".format(self.id, self.act_type, self.value)



map_misp_to_act: Dict[Text, Callable[[Text], Tuple[Optional[Text], Optional[Text]]]] = {
    "authentihash": objmapper.hash_f,
    "campaign-name": objmapper.campaign_f,
    "hostname": objmapper.fqdn_f,
    "domain": objmapper.fqdn_f,
    "impfuzzy": objmapper.hash_f,
    "imphash": objmapper.hash_f,
    "ip-dst": objmapper.ip_f,
    "ip-src": objmapper.ip_f,
    "link": objmapper.uri_f,
    "md5": objmapper.hash_f,
    "mutex": objmapper.mutex_f,
    "sha1": objmapper.hash_f,
    "sha224": objmapper.hash_f,
    "sha256": objmapper.hash_f,
    "sha384": objmapper.hash_f,
    "sha512/224": objmapper.hash_f,
    "sha512/256": objmapper.hash_f,
    "sha512": objmapper.hash_f,
    "ssdeep": objmapper.hash_f,
    "threat-actor": objmapper.threat_actor_f,
    "url": objmapper.uri_f,
    "user-agent": objmapper.user_agent_f,
    "vulnerability": objmapper.vulnerability_f,
    "whois-registrant-email": objmapper.email_f,
    "whois-registrant-name": objmapper.person_f,
    "whois-registrar": objmapper.organization_f,
    "x509-fingerprint-sha1": objmapper.certificate_f,
}


class IncompleteEventException(Exception):
    pass
