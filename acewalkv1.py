#!/usr/bin/env python3
"""
AceWalk v1 - minimal collector that builds a dictionary of LDAP objects and their ACEs.
"""

import argparse
import logging
import sys
from uuid import UUID

from impacket.examples import logger
from impacket.examples.utils import parse_identity, ldap_login
from impacket.ldap import ldap, ldapasn1
from impacket.ldap.ldaptypes import LDAP_SID, LDAP_SERVER_SD_FLAGS, SR_SECURITY_DESCRIPTOR
from impacket.msada_guids import SCHEMA_OBJECTS, EXTENDED_RIGHTS
import version


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


def summarize_perms(perms):
    if not perms:
        return "-"
    if "GENERIC_ALL" in perms:
        return "GENERIC_ALL"
    if "FULL_CONTROL" in perms:
        return "FULL_CONTROL"
    if "GENERIC_WRITE" in perms:
        return "GENERIC_WRITE"
    if "ADS_RIGHT_DS_CONTROL_ACCESS" in perms:
        return "DS_CONTROL_ACCESS"
    return "\n".join(perms)


def resolve_guid_name(guid: str):
    if not guid:
        return None
    g = guid.lower()
    if g in EXTENDED_RIGHTS:
        return EXTENDED_RIGHTS[g]
    if g in SCHEMA_OBJECTS:
        return SCHEMA_OBJECTS[g]
    return None


def rights_to_names(ace: dict) -> list[str]:
    names = []
    mask = ace.get("Mask", "")
    perms = ace.get("Permissions") or []
    obj_type_guid = ace.get("ObjectType")
    obj_type_name = resolve_guid_name(obj_type_guid)

    member_guid = "bf9679c0-0de6-11d0-a285-00aa003049e2"

    if "GENERIC_ALL" in perms:
        names.append("GenericAll")
        return names
    if "FULL_CONTROL" in perms:
        names.append("FullControl")

    if "GENERIC_WRITE" in perms:
        names.append("GenericWrite")
    if "WRITE_DACL" in perms:
        names.append("WriteDacl")
    if "WRITE_OWNER" in perms:
        names.append("WriteOwner")
    if "DELETE" in perms:
        names.append("Delete")

    if "ADS_RIGHT_DS_WRITE_PROP" in perms:
        if obj_type_guid and obj_type_guid.lower() == member_guid:
            names.append("AddMember")
        else:
            names.append("WriteProperty")

    if "ADS_RIGHT_DS_CONTROL_ACCESS" in perms:
        if obj_type_name:
            names.append(f"ControlAccess({obj_type_name})")
        elif obj_type_guid:
            names.append(f"ControlAccess({obj_type_guid})")
        else:
            names.append("ControlAccess")

    if "ADS_RIGHT_DS_SELF" in perms:
        names.append("Self")
    if "ADS_RIGHT_DS_CREATE_CHILD" in perms:
        names.append("CreateChild")
    if "ADS_RIGHT_DS_DELETE_CHILD" in perms:
        names.append("DeleteChild")
    if "ADS_RIGHT_DS_READ_PROP" in perms:
        names.append("ReadProperty")

    # Fallback: include raw permissions if nothing mapped
    if not names:
        names.extend(perms)

    # append object type name/guid context if available
    if obj_type_name:
        names = [f"{n} ({obj_type_name})" for n in names]
    elif obj_type_guid:
        names = [f"{n} ({obj_type_guid})" for n in names]

    return names


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

    def collect(self, ldap_conn):
        search_filter = "(nTSecurityDescriptor=*)"
        attributes = ["distinguishedName", "nTSecurityDescriptor", "objectSid", "objectClass", "sAMAccountName"]

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
                    except Exception:
                        pass
                elif attr_type == "objectClass":
                    obj_dict["objectClass"] = [str(v).lower() for v in attribute["vals"]]
                elif attr_type == "sAMAccountName":
                    obj_dict["sAMAccountName"] = str(attribute["vals"][0])
                elif attr_type == "nTSecurityDescriptor" and len(attribute["vals"]) > 0:
                    sd_raw = bytes(attribute["vals"][0])
                    sd = SR_SECURITY_DESCRIPTOR(data=sd_raw)
                    d_acl = sd["Dacl"]
                    if d_acl:
                        for ace in d_acl.aces:
                            obj_dict["Aces"].append(parse_ace(ace))

            self.objects[dn] = obj_dict

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

        self.collect(ldap_conn)

        search_sid = self.resolve_identity_to_sid(ldap_conn, self.options.identity)
        if not search_sid:
            print(f"[!] Identity '{self.options.identity}' not found")
            return

        print(f"[+] Loaded {len(self.objects)} objects with ACEs")
        print(f"[*] Enumerating ACEs for: {self.options.identity} (SID: {search_sid})")

        rows = []
        edges = self.edges_from_sid(search_sid)
        for e in edges:
            tgt = e["target_obj"]
            ace = e["ace"]
            perms_line = "\n".join(rights_to_names(ace))

            rows.append(
                {
                    "dn": tgt.get("DistinguishedName", ""),
                    "ace_type": ace.get("TypeName") or "-",
                    "mask": ace.get("Mask") or "-",
                    "perms": perms_line,
                    "obj_type": ace.get("ObjectType") or "-",
                    "inh_obj_type": ace.get("InheritedObjectType") or "-",
                }
            )

        if not rows:
            print("[!] No ACEs found for this identity")
            return

        headers = [
            ("DN", "dn"),
            ("ACE Type", "ace_type"),
            ("Mask", "mask"),
            ("Perms", "perms"),
            ("ObjectType", "obj_type"),
            ("InheritedObjType", "inh_obj_type"),
        ]

        col_widths = {}
        for title, key in headers:
            max_len = len(title)
            for r in rows:
                # For perms, account for multi-line content
                if key == "perms":
                    lines = str(r.get(key, "")).split("\n")
                    for ln in lines:
                        if len(ln) > max_len:
                            max_len = len(ln)
                else:
                    v = str(r.get(key, ""))
                    if len(v) > max_len:
                        max_len = len(v)
            col_widths[key] = max_len

        def fmt(val, key):
            s = str(val)
            return s.ljust(col_widths[key])

        header_line = "  ".join(fmt(title, key) for title, key in headers)
        sep_line = "-" * len(header_line)
        print(header_line)
        print(sep_line)

        for r in rows:
            perms_lines = str(r.get("perms", "")).split("\n")
            base_parts = []
            for title, key in headers:
                if key == "perms":
                    base_parts.append(fmt(perms_lines[0], key))
                else:
                    base_parts.append(fmt(r.get(key, ""), key))
            print("  ".join(base_parts))

            if len(perms_lines) > 1:
                for extra in perms_lines[1:]:
                    extra_parts = []
                    for title, key in headers:
                        if key == "perms":
                            extra_parts.append(fmt(extra, key))
                        else:
                            extra_parts.append(" " * col_widths[key])
                    print("  ".join(extra_parts))


def main():
    print(version.BANNER)
    parser = argparse.ArgumentParser(add_help=True, description="AceWalk v1 collector")
    parser.add_argument("target", action="store", help="[[domain/]username[:password]]")
    parser.add_argument("-identity", required=True, action="store", metavar="identity", help="Identity to search (sAMAccountName, DN, or SID)",)

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
        logging.debug("Exception:", exc_info=True)
        logging.error(str(e))


if __name__ == "__main__":
    main()
