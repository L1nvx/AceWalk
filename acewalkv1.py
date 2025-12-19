#!/usr/bin/env python3
"""
AceWalk v1 - minimal collector that builds a dictionary of LDAP objects and their ACEs.
"""

import argparse
import logging
import sys
from uuid import UUID
from collections import defaultdict
import textwrap
import version

from impacket.examples import logger
from impacket.examples.utils import parse_identity, ldap_login
from impacket.ldap import ldap, ldapasn1
from impacket.ldap.ldaptypes import LDAP_SID, LDAP_SERVER_SD_FLAGS, SR_SECURITY_DESCRIPTOR
from impacket.msada_guids import SCHEMA_OBJECTS, EXTENDED_RIGHTS
import impacket


ACCESS_FLAGS = {
    "GENERIC_READ": 0x80000000,
    "GENERIC_WRITE": 0x40000000,
    "GENERIC_EXECUTE": 0x20000000,
    "GENERIC_ALL": 0x10000000,
    "MAXIMUM_ALLOWED": 0x02000000,
    "ACCESS_SYSTEM_SECURITY": 0x01000000,
    "SYNCHRONIZE": 0x00100000,
    "FULL_CONTROL": 0x000F01FF,
    "WRITE_OWNER": 0x00080000,
    "WRITE_DACL": 0x00040000,
    "READ_CONTROL": 0x00020000,
    "DELETE": 0x00010000,
    "ADS_RIGHT_DS_CONTROL_ACCESS": 0x00000100,
    "ADS_RIGHT_DS_CREATE_CHILD": 0x00000001,
    "ADS_RIGHT_DS_DELETE_CHILD": 0x00000002,
    "ADS_RIGHT_DS_READ_PROP": 0x00000010,
    "ADS_RIGHT_DS_WRITE_PROP": 0x00000020,
    "ADS_RIGHT_DS_SELF": 0x00000008,
}

ACE_WITH_OBJECTTYPE = {
    0x05,
    0x06,
    0x07,
    0x08,
    0x0B,
    0x0C,
    0x0F,
    0x10,
}


def parse_ace(ace) -> dict:
    ace_type = int(ace["AceType"])
    ace_flags = int(ace["AceFlags"])
    ace_typename = ace["TypeName"]
    acc = ace["Ace"]
    mask = acc["Mask"]

    permissions = []
    for name, flag in ACCESS_FLAGS.items():
        try:
            if mask.hasPriv(flag):
                permissions.append(name)
        except Exception:
            pass

    object_type = None
    inherited_object_type = None

    if ace_type in ACE_WITH_OBJECTTYPE:
        try:
            raw_objtype = acc["ObjectType"]
            if raw_objtype and len(bytes(raw_objtype)) == 16:
                object_type = str(UUID(bytes_le=bytes(raw_objtype)))
        except Exception:
            pass
        try:
            raw_inh = acc["InheritedObjectType"]
            if raw_inh and len(bytes(raw_inh)) == 16:
                inherited_object_type = str(UUID(bytes_le=bytes(raw_inh)))
        except Exception:
            pass

    return {
        "TypeName": ace_typename,
        "AceType": ace_type,
        "AceFlags": ace_flags,
        "Mask": f"0x{int(str(mask), 16):08x}",
        "SecurityIdentifier": acc["Sid"].formatCanonical(),
        "Permissions": permissions,
        "ObjectType": object_type,
        "InheritedObjectType": inherited_object_type,
    }


def effect_from_typename(type_name: str) -> str:
    t = (type_name or "").upper()
    if "DENIED" in t:
        return "DENY"
    if "ALLOWED" in t:
        return "ALLOW"
    if "AUDIT" in t:
        return "AUDIT"
    return "OTHER"


def obj_name(obj_dict: dict) -> str:
    if obj_dict.get("sAMAccountName"):
        return obj_dict["sAMAccountName"]
    dn = obj_dict.get("DistinguishedName", "")
    if dn:
        return dn.split(",")[0].replace("CN=", "")
    return "(unknown)"


def dn_parent(dn: str) -> str | None:
    if not dn or "," not in dn:
        return None
    return dn.split(",", 1)[1].strip()


def resolve_guid_name(guid: str):
    if not guid:
        return None
    g = guid.lower()
    if g in SCHEMA_OBJECTS:
        return SCHEMA_OBJECTS[g]
    if g in EXTENDED_RIGHTS:
        return EXTENDED_RIGHTS[g]
    return None


def rights_to_names(ace: dict, target_obj: dict) -> list[str]:
    """
    Convierte ACE a nombres descriptivos similares a BloodHound.
    Incluye el nombre del atributo/derecho entre paréntesis cuando es relevante.
    """
    names = []
    perms = ace.get("Permissions") or []
    obj_type_guid = ace.get("ObjectType")
    ace_type = ace.get("AceType")
    obj_type_name = resolve_guid_name(obj_type_guid) if obj_type_guid else None

    obj_classes = target_obj.get("objectClass", [])
    entry_type = None
    if "user" in obj_classes:
        entry_type = "user"
    elif "group" in obj_classes:
        entry_type = "group"
    elif "computer" in obj_classes:
        entry_type = "computer"
    elif "organizationalunit" in obj_classes:
        entry_type = "organizational-unit"
    elif "grouppolicycontainer" in obj_classes:
        entry_type = "gpo"
    elif "domain" in obj_classes or "domaindns" in obj_classes:
        entry_type = "domain"
    GUID_WRITE_MEMBER = "bf9679c0-0de6-11d0-a285-00aa003049e2"
    GUID_USER_FORCE_CHANGE_PASSWORD = "00299570-246d-11d0-a768-00aa006e0529"
    GUID_ALLOWED_TO_ACT = "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79"
    GUID_GET_CHANGES = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
    GUID_GET_CHANGES_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
    GUID_GET_CHANGES_FILTERED = "89e95b76-444d-4c62-991a-0facbeda640c"
    GUID_SPN = "f3a64788-5306-11d1-a9c5-0000f80367c1"
    GUID_KEY_CREDENTIAL_LINK = "5b47d60f-6090-40b2-9f37-2a4de88f3063"
    GUID_WRITE_GPLINK = "f30e3bbe-9ff0-11d1-b603-0000f80367c1"
    GUID_USER_ACCOUNT_RESTRICTIONS = "4c164200-20c0-11d0-a768-00aa006e0529"
    
    obj_guid_lower = obj_type_guid.lower() if obj_type_guid else None

    if "GENERIC_ALL" in perms or "FULL_CONTROL" in perms:
        if ace_type in ACE_WITH_OBJECTTYPE and obj_guid_lower:
            pass
        else:
            names.append("GenericAll")
            return names

    if "GENERIC_WRITE" in perms:
        names.append("GenericWrite")
        if entry_type not in ["domain", "computer"]:
            return names

    if "WRITE_DACL" in perms:
        names.append("WriteDacl")

    if "WRITE_OWNER" in perms:
        names.append("WriteOwner")

    if "ADS_RIGHT_DS_WRITE_PROP" in perms:
        if not obj_type_guid and entry_type in ['user', 'group', 'computer', 'gpo', 'organizational-unit']:
            if "GenericWrite" not in names:
                names.append("GenericWrite")
        
        elif entry_type == "group" and obj_guid_lower == GUID_WRITE_MEMBER:
            if obj_type_name:
                names.append(f"AddMember ({obj_type_name})")
            else:
                names.append("AddMember")
        
        elif entry_type == "computer" and obj_guid_lower == GUID_ALLOWED_TO_ACT:
            if obj_type_name:
                names.append(f"AddAllowedToAct ({obj_type_name})")
            else:
                names.append("AddAllowedToAct")
        
        elif entry_type in ["user", "computer"] and obj_guid_lower == GUID_USER_ACCOUNT_RESTRICTIONS:
            if obj_type_name:
                names.append(f"WriteAccountRestrictions ({obj_type_name})")
            else:
                names.append("WriteAccountRestrictions")
        
        elif entry_type == "organizational-unit" and obj_guid_lower == GUID_WRITE_GPLINK:
            if obj_type_name:
                names.append(f"WriteGPLink ({obj_type_name})")
            else:
                names.append("WriteGPLink")
        
        elif entry_type in ["user", "computer"] and obj_guid_lower == GUID_KEY_CREDENTIAL_LINK:
            if obj_type_name:
                names.append(f"AddKeyCredentialLink ({obj_type_name})")
            else:
                names.append("AddKeyCredentialLink")
        
        elif entry_type in ["user", "computer"] and obj_guid_lower == GUID_SPN:
            if obj_type_name:
                names.append(f"WriteSPN ({obj_type_name})")
            else:
                names.append("WriteSPN")
        
        elif obj_type_name:
            names.append(f"WriteProperty ({obj_type_name})")
        else:
            names.append("WriteProperty")

    if "ADS_RIGHT_DS_SELF" in perms:
        if entry_type == "group" and obj_guid_lower == GUID_WRITE_MEMBER:
            if obj_type_name:
                names.append(f"AddSelf ({obj_type_name})")
            else:
                names.append("AddSelf")
        elif obj_type_name:
            names.append(f"Self ({obj_type_name})")
        else:
            names.append("Self")

    if "ADS_RIGHT_DS_CONTROL_ACCESS" in perms:
        if not obj_type_guid:
            if entry_type in ["user", "domain", "computer"]:
                names.append("AllExtendedRights")
        else:
            if entry_type in ["user", "computer"] and obj_guid_lower == GUID_USER_FORCE_CHANGE_PASSWORD:
                if obj_type_name:
                    names.append(f"ForceChangePassword ({obj_type_name})")
                else:
                    names.append("ForceChangePassword")
            
            elif entry_type == "domain":
                if obj_guid_lower == GUID_GET_CHANGES:
                    if obj_type_name:
                        names.append(f"GetChanges ({obj_type_name})")
                    else:
                        names.append("GetChanges")
                elif obj_guid_lower == GUID_GET_CHANGES_ALL:
                    if obj_type_name:
                        names.append(f"GetChangesAll ({obj_type_name})")
                    else:
                        names.append("GetChangesAll")
                elif obj_guid_lower == GUID_GET_CHANGES_FILTERED:
                    if obj_type_name:
                        names.append(f"GetChangesInFilteredSet ({obj_type_name})")
                    else:
                        names.append("GetChangesInFilteredSet")
                elif obj_type_name:
                    names.append(f"ExtendedRight ({obj_type_name})")
                else:
                    names.append("ExtendedRight")
            
            elif obj_type_name:
                names.append(f"ExtendedRight ({obj_type_name})")
            else:
                names.append("ExtendedRight")

    if "ADS_RIGHT_DS_READ_PROP" in perms:
        if entry_type == "computer" and "ADS_RIGHT_DS_CONTROL_ACCESS" in perms:
            LAPS_GUIDS = [
                "ms-mcs-admpwd",
                "ms-laps-password", 
                "ms-laps-encryptedpassword"
            ]
            if obj_type_name and obj_type_name.lower() in LAPS_GUIDS:
                names.append(f"ReadLAPSPassword ({obj_type_name})")
        
        if not names:
            if obj_type_name:
                names.append(f"ReadProperty ({obj_type_name})")
            else:
                names.append("ReadProperty")

    if "ADS_RIGHT_DS_CREATE_CHILD" in perms:
        if obj_type_name:
            names.append(f"CreateChild ({obj_type_name})")
        else:
            names.append("CreateChild")
    
    if "ADS_RIGHT_DS_DELETE_CHILD" in perms:
        if obj_type_name:
            names.append(f"DeleteChild ({obj_type_name})")
        else:
            names.append("DeleteChild")
    
    if "DELETE" in perms:
        names.append("Delete")

    if not names:
        names = [p for p in perms if p not in ["READ_CONTROL", "SYNCHRONIZE"]]
    
    return names if names else ["-"]

def wrap_cell(value: str, width: int) -> list[str]:
    """
    Wrap a single cell to the given width, padding each line so table columns stay aligned.
    """
    text = "-" if value is None or str(value) == "" else str(value)
    wrapped = textwrap.wrap(text, width=width) or [""]
    return [line.ljust(width) for line in wrapped]


def wrap_rights(rights: list[str], width: int) -> list[str]:
    """
    Wrap each right and flatten into a single list so multiple rights render on separate lines.
    """
    if not rights:
        rights = ["-"]
    lines: list[str] = []
    for r in rights:
        lines.extend(wrap_cell(r, width))
    return lines


class AceCollector:
    def __init__(self, username, password, domain, options):
        self.username = username
        self.password = password
        self.domain = domain
        self.options = options

        self.lmhash = ""
        self.nthash = ""
        if options.hashes:
            self.lmhash, self.nthash = options.hashes.split(":")

        self.base_dn = ",".join([f"dc={p}" for p in domain.split(".")])
        self.objects = {}
        self.sid_map = {}
        self.children_index = defaultdict(list)

    def collect(self, ldap_conn):
        search_filter = "(nTSecurityDescriptor=*)"
        attributes = ["distinguishedName", "nTSecurityDescriptor", "objectSid", "objectClass", "sAMAccountName", "memberOf"]

        sd_control = ldapasn1.SDFlagsControl(
            criticality=True,
            flags=LDAP_SERVER_SD_FLAGS.DACL_SECURITY_INFORMATION.value,
        )

        resp = ldap_conn.search(
            searchBase=self.base_dn,
            scope=2,
            searchFilter=search_filter,
            attributes=attributes,
            searchControls=[sd_control],
        )

        for item in resp:
            if not isinstance(item, ldapasn1.SearchResultEntry):
                continue

            dn = str(item["objectName"])
            obj_dict = {"DistinguishedName": dn, "Aces": []}

            for attribute in item["attributes"]:
                attr_type = str(attribute["type"])
                if attr_type == "objectSid":
                    try:
                        sid_bytes = bytes(attribute["vals"][0])
                        obj_dict["ObjectSid"] = LDAP_SID(sid_bytes).formatCanonical()
                        self.sid_map[obj_dict["ObjectSid"]] = dn
                    except Exception:
                        pass
                elif attr_type == "objectClass":
                    obj_dict["objectClass"] = [str(v).lower() for v in attribute["vals"]]
                elif attr_type == "sAMAccountName":
                    obj_dict["sAMAccountName"] = str(attribute["vals"][0])
                elif attr_type == "memberOf":
                    try:
                        obj_dict["memberOf"] = [str(v) for v in attribute["vals"]]
                    except Exception:
                        obj_dict["memberOf"] = []
                elif attr_type == "nTSecurityDescriptor" and len(attribute["vals"]) > 0:
                    sd_raw = bytes(attribute["vals"][0])
                    sd = SR_SECURITY_DESCRIPTOR(data=sd_raw)
                    d_acl = sd["Dacl"]
                    if d_acl:
                        for ace in d_acl.aces:
                            obj_dict["Aces"].append(parse_ace(ace))

            self.objects[dn] = obj_dict
            parent_dn = dn_parent(dn)
            if parent_dn:
                self.children_index[parent_dn].append(obj_dict)

    def resolve_identity_to_sid(self, ldap_conn, identity: str):
        if identity.startswith("S-1-"):
            return identity
        if "," in identity and "=" in identity:
            obj = self.objects.get(identity)
            if obj:
                return obj.get("ObjectSid")
            return None

        try:
            search_filter = f"(sAMAccountName={identity})"
            resp = ldap_conn.search(
                searchBase=self.base_dn,
                scope=2,
                searchFilter=search_filter,
                attributes=["objectSid"],
            )
            for item in resp:
                if isinstance(item, ldapasn1.SearchResultEntry):
                    for attr in item["attributes"]:
                        if str(attr["type"]) == "objectSid":
                            sid_bytes = bytes(attr["vals"][0])
                            sid_obj = LDAP_SID(sid_bytes)
                            return sid_obj.formatCanonical()
        except Exception:
            return None
        return None

    def edges_from_sid(self, sid: str):
        edges = []
        for dn, obj in self.objects.items():
            obj_sid = obj.get("ObjectSid")
            for ace in obj.get("Aces", []):
                if ace.get("SecurityIdentifier") != sid:
                    continue
                edges.append(
                    {
                        "target_dn": dn,
                        "target_obj": obj,
                        "ace": ace,
                        "target_sid": obj_sid,
                        "effect": effect_from_typename(ace.get("TypeName")),
                    }
                )
        return edges

    def run(self):
        ldap_conn = ldap_login(
            self.options.target_host,
            self.base_dn,
            self.options.dc_ip,
            self.options.dc_host,
            self.options.k,
            self.username,
            self.password,
            self.domain,
            self.lmhash,
            self.nthash,
            self.options.aesKey,
        )

        logging.debug(f"Collecting objects from {self.base_dn}...")
        self.collect(ldap_conn)

        base_sid = self.resolve_identity_to_sid(ldap_conn, self.options.identity)
        if not base_sid:
            logging.error(f"Identity '{self.options.identity}' not found")
            return

        logging.debug(f"Loaded {len(self.objects)} objects with ACEs")
        logging.debug(f"Enumerating ACEs for: {self.options.identity} (SID: {base_sid})")

        rows = []
        sid_labels = []
        base_label = self.options.identity
        base_dn = self.sid_map.get(base_sid)
        
        if base_dn and base_dn in self.objects:
            obj = self.objects[base_dn]
            base_label = obj.get("sAMAccountName") or base_dn
            
            sid_labels.append((base_sid, f"DIRECT", base_label))
            
            logging.debug("Checking group memberships...")
            for m_dn in obj.get("memberOf", []):
                m_obj = self.objects.get(m_dn)
                if m_obj and m_obj.get("ObjectSid"):
                    label = m_obj.get("sAMAccountName") or m_dn.split(",")[0].replace("CN=", "")
                    sid_labels.append((m_obj["ObjectSid"], "GROUP", label))
            
            children = self.children_index.get(base_dn, [])
            if children:
                logging.debug(f"Checking children objects ({len(children)} found)...")
                for child in children:
                    c_sid = child.get("ObjectSid")
                    if c_sid:
                        c_label = child.get("sAMAccountName") or child.get("DistinguishedName", "").split(",")[0].replace("CN=", "")
                        sid_labels.append((c_sid, "CHILD", c_label))
        else:
            sid_labels.append((base_sid, "DIRECT", base_label))

        logging.debug(f"Searching ACEs for {len(sid_labels)} identities (direct + groups + children)...")
        
        for sid, relation_type, label in sid_labels:
            edges = self.edges_from_sid(sid)
            for e in edges:
                tgt = e["target_obj"]
                ace = e["ace"]
                rights_list = rights_to_names(ace, tgt)
                
                obj_type_guid = ace.get("ObjectType")
                obj_type_display = resolve_guid_name(obj_type_guid) if obj_type_guid else "-"
                
                inh_obj_type_guid = ace.get("InheritedObjectType")
                inh_obj_type_display = resolve_guid_name(inh_obj_type_guid) if inh_obj_type_guid else "-"

                row_data = {
                    "relation": relation_type,
                    "who": label,
                    "dn": tgt.get("DistinguishedName", ""),
                    "rights": rights_list,
                }
                
                if self.options.extended:
                    row_data.update({
                        "obj_type": obj_type_guid,
                        "ace_type": ace.get("TypeName") or "-",
                        "mask": ace.get("Mask") or "-",
                        "inh_obj_type": inh_obj_type_display,
                    })
                
                rows.append(row_data)

        if not rows:
            logging.warning("No ACEs found for this identity (including groups and children)")
            return

        if self.options.extended:
            headers = [
                ("Relation", "relation", 10),
                ("Trustee", "who", 20),
                ("Target DN", "dn", 50),
                ("Rights", "rights", 40),
                ("ObjectType", "obj_type", 30),
                ("ACE Type", "ace_type", 30),
                ("Mask", "mask", 12),
                ("InheritedObjType", "inh_obj_type", 30),
            ]
        else:
            headers = [
                ("Relation", "relation", 10),
                ("Trustee", "who", 20),
                ("Target DN", "dn", 60),
                ("Rights", "rights", 50),
            ]

        header_line = "  ".join(title.ljust(width) for title, _, width in headers)
        sep_line = "  ".join("-" * width for _, _, width in headers)
        
        print(header_line)
        print(sep_line)

        for r in rows:
            column_lines = []
            for _, key, width in headers:
                if key == "rights":
                    column_lines.append((wrap_rights(r.get("rights", []), width), width))
                else:
                    column_lines.append((wrap_cell(r.get(key, ""), width), width))

            max_lines = max(len(lines) for lines, _ in column_lines)

            for line_idx in range(max_lines):
                parts = []
                for lines, width in column_lines:
                    if line_idx < len(lines):
                        parts.append(lines[line_idx])
                    else:
                        parts.append(" " * width)
                print("  ".join(parts))
        
        print("")


def main():
    print(version.BANNER)
    parser = argparse.ArgumentParser(add_help=True, description="AceWalk v1 - LDAP ACE collector")
    parser.add_argument("target", action="store", help="[[domain/]username[:password]]")
    parser.add_argument("-identity", required=True, action="store", metavar="identity", 
                       help="Identity to search (sAMAccountName, DN, or SID)")
    parser.add_argument("-extended", action="store_true", 
                       help="Show extended table with ACE Type, Mask, and InheritedObjectType")

    parser.add_argument("-ts", action="store_true", help="Adds timestamp to every logging output")
    parser.add_argument("-debug", action="store_true", help="Turn DEBUG output ON")

    auth = parser.add_argument_group("authentication")
    auth.add_argument("-hashes", action="store", metavar="LMHASH:NTHASH", help="NTLM hashes LMHASH:NTHASH")
    auth.add_argument("-no-pass", action="store_true", help="don't ask for password (useful for -k)")
    auth.add_argument("-k", action="store_true", help="Use Kerberos authentication (ccache).")
    auth.add_argument("-aesKey", action="store", metavar="hex key", help="AES key for Kerberos (128/256 bits)")

    conn = parser.add_argument_group("connection")
    conn.add_argument("-dc-ip", action="store", metavar="ip address", help="IP Address of the domain controller.")
    conn.add_argument("-dc-host", action="store", metavar="hostname", help="Hostname of the domain controller to use.")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()
    
    logger.init(options.ts, options.debug)

    domain, username, password, _, _, options.k = parse_identity(
        options.target, options.hashes, options.no_pass, options.aesKey, options.k
    )

    if domain == "":
        logging.critical("Domain should be specified!")
        sys.exit(1)

    options.target_host = options.dc_host or options.dc_ip or domain

    try:
        collector = AceCollector(username, password, domain, options)
        collector.run()
    except ldap.LDAPSessionError as e:
        logging.error(str(e))
    except Exception as e:
        if options.debug:
            import traceback
            traceback.print_exc()
        else:
            logging.error(str(e))


if __name__ == "__main__":
    main()
