#!/usr/bin/env python3
"""
ACLWalk - LDAP ACL graph visualizer (Rich, merged, container-children expansion)
"""

import version
import argparse
import sys
import logging
from uuid import UUID
from collections import defaultdict

from impacket.examples import logger
from impacket.examples.utils import parse_identity, ldap_login
from impacket.ldap import ldap, ldapasn1
from impacket.ldap.ldaptypes import LDAP_SID, LDAP_SERVER_SD_FLAGS, SR_SECURITY_DESCRIPTOR
from impacket.msada_guids import SCHEMA_OBJECTS, EXTENDED_RIGHTS

try:
    from rich.console import Console
    import renderer_rich
except Exception:
    Console = None
    renderer_rich = None


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

ACE_WITH_OBJECTTYPE = [
    0x05,
    0x06,
    0x07,
    0x08,
    0x0B,
    0x0C,
    0x0F,
    0x10,
]


def mask_has(mask: int, flag_name: str) -> bool:
    v = ACCESS_FLAGS.get(flag_name)
    if v is None:
        return False
    return (mask & v) == v


def effect_from_typename(type_name: str) -> str:
    tn = (type_name or "").upper()
    if "DENIED" in tn:
        return "DENY"
    if "AUDIT" in tn:
        return "AUDIT"
    if "ALLOWED" in tn:
        return "ALLOW"
    return "OTHER"


def severity_from_mask(mask: int) -> str:
    if (
        mask_has(mask, "GENERIC_ALL")
        or mask_has(mask, "FULL_CONTROL")
        or mask_has(mask, "WRITE_DACL")
        or mask_has(mask, "WRITE_OWNER")
    ):
        return "CRIT"

    if (
        mask_has(mask, "GENERIC_WRITE")
        or mask_has(mask, "ADS_RIGHT_DS_CONTROL_ACCESS")
        or mask_has(mask, "ADS_RIGHT_DS_WRITE_PROP")
        or mask_has(mask, "ADS_RIGHT_DS_SELF")
    ):
        return "HIGH"

    if (
        mask_has(mask, "ADS_RIGHT_DS_CREATE_CHILD")
        or mask_has(mask, "ADS_RIGHT_DS_DELETE_CHILD")
        or mask_has(mask, "DELETE")
        or mask_has(mask, "ACCESS_SYSTEM_SECURITY")
    ):
        return "MED"

    if mask_has(mask, "GENERIC_READ") or mask_has(mask, "READ_CONTROL") or mask_has(mask, "ADS_RIGHT_DS_READ_PROP"):
        return "LOW"

    return "INFO"


def sev_rank(sev: str) -> int:
    return {"CRIT": 0, "HIGH": 1, "MED": 2, "LOW": 3, "INFO": 4}.get(sev, 5)


def effect_rank(effect: str) -> int:
    return {"DENY": 0, "ALLOW": 1, "AUDIT": 2, "OTHER": 3}.get(effect, 4)


def dn_parent(dn: str) -> str | None:
    if not dn or "," not in dn:
        return None
    return dn.split(",", 1)[1].strip()


class AclWalk:
    def __init__(self, username, password, domain, cmdLineOptions):
        self.__username = username
        self.__password = password
        self.__domain = domain

        self.__lmhash = ""
        self.__nthash = ""
        self.__no_pass = cmdLineOptions.no_pass
        self.__aesKey = cmdLineOptions.aesKey
        self.__doKerberos = cmdLineOptions.k
        self.__kdcIP = cmdLineOptions.dc_ip
        self.__kdcHost = cmdLineOptions.dc_host

        self.__search_identity = cmdLineOptions.identity
        self.__max_depth = getattr(cmdLineOptions, "max_depth", 6)
        self.__no_emoji = False

        # Limits to keep output sane
        raw_max_targets = getattr(cmdLineOptions, "max_targets", 30)
        self.__max_targets = raw_max_targets if raw_max_targets and raw_max_targets > 0 else None

        raw_max_children = getattr(cmdLineOptions, "max_children", 50)
        self.__max_children = raw_max_children if raw_max_children and raw_max_children > 0 else None

        raw_max_child_trustees = getattr(cmdLineOptions, "max_child_trustees", 25)
        self.__max_child_trustees = raw_max_child_trustees if raw_max_child_trustees and raw_max_child_trustees > 0 else None

        # Policy
        self.__include_deny = True
        self.__include_audit = True
        self.__only_expand_principals = False

        self.__target = self.__kdcHost or self.__kdcIP or self.__domain

        if cmdLineOptions.hashes is not None:
            self.__lmhash, self.__nthash = cmdLineOptions.hashes.split(":")

        self.baseDN = ",".join([f"dc={p}" for p in self.__domain.split(".")])

        self.objects = {}
        self.sid_map = {}
        self.children_index = defaultdict(list)

    @staticmethod
    def resolve_guid(guid_str):
        if guid_str is None:
            return None
        guid_lower = guid_str.lower()
        if guid_lower in EXTENDED_RIGHTS:
            return EXTENDED_RIGHTS[guid_lower]
        if guid_lower in SCHEMA_OBJECTS:
            return SCHEMA_OBJECTS[guid_lower]
        return guid_str

    def parse_ace(self, ace):
        aceType = int(ace["AceType"])
        aceTypeName = ace["TypeName"]
        acc = ace["Ace"]
        mask_int = int(acc["Mask"]["Mask"])
        sid = acc["Sid"].formatCanonical()

        permissions = []
        for name, flag in ACCESS_FLAGS.items():
            if (mask_int & flag) == flag:
                permissions.append(name)

        objectType = None
        objectTypeName = None

        if aceType in ACE_WITH_OBJECTTYPE:
            try:
                raw_objtype = None
                try:
                    raw_objtype = acc["ObjectType"]
                except Exception:
                    raw_objtype = None

                if raw_objtype and len(bytes(raw_objtype)) == 16:
                    objectType = str(UUID(bytes_le=bytes(raw_objtype)))
                    objectTypeName = self.resolve_guid(objectType)
            except (KeyError, ValueError):
                pass

        return {
            "type": aceType,
            "typeName": aceTypeName,
            "mask": mask_int,
            "sid": sid,
            "permissions": permissions,
            "objectType": objectType,
            "objectTypeName": objectTypeName,
        }

    def load_all_objects(self, ldapConnection):
        logging.info("Loading all objects and ACEs from LDAP...")

        searchFilter = "(nTSecurityDescriptor=*)"
        attributes = [
            "distinguishedName",
            "nTSecurityDescriptor",
            "objectClass",
            "sAMAccountName",
            "objectSid",
            "displayName",
            "description",
            "memberOf",
            "objectGUID",
        ]

        sd_control = ldapasn1.SDFlagsControl(
            criticality=True,
            flags=LDAP_SERVER_SD_FLAGS.DACL_SECURITY_INFORMATION.value,
        )

        resp = ldapConnection.search(
            searchBase=self.baseDN,
            scope=2,
            searchFilter=searchFilter,
            attributes=attributes,
            searchControls=[sd_control],
        )

        logging.info(f"Total records returned: {len(resp)}")

        for item in resp:
            if not isinstance(item, ldapasn1.SearchResultEntry):
                continue

            dn = str(item["objectName"])
            obj_data = {"dn": dn, "aces": [], "attr": {}, "memberOf": []}

            for attribute in item["attributes"]:
                attr_type = str(attribute["type"])

                if attr_type == "objectClass":
                    obj_data["objectClass"] = [str(v).lower() for v in attribute["vals"]]

                elif attr_type == "sAMAccountName":
                    obj_data["samAccountName"] = str(attribute["vals"][0])

                elif attr_type in ("displayName", "description"):
                    try:
                        obj_data["attr"][attr_type] = str(attribute["vals"][0])
                    except Exception:
                        pass

                elif attr_type == "memberOf":
                    try:
                        obj_data["memberOf"] = [str(v) for v in attribute["vals"]]
                    except Exception:
                        pass

                elif attr_type == "objectSid":
                    try:
                        sid_bytes = bytes(attribute["vals"][0])
                        sid_obj = LDAP_SID(sid_bytes)
                        obj_data["sid"] = sid_obj.formatCanonical()
                        self.sid_map[obj_data["sid"]] = dn
                    except Exception:
                        pass

                elif attr_type == "objectGUID":
                    try:
                        guid_bytes = bytes(attribute["vals"][0])
                        obj_data["objectGUID"] = str(UUID(bytes_le=guid_bytes))
                    except Exception:
                        pass

                elif attr_type == "nTSecurityDescriptor":
                    if len(attribute["vals"]) > 0:
                        sd_raw = bytes(attribute["vals"][0])
                        sd = SR_SECURITY_DESCRIPTOR(data=sd_raw)

                        dAcl = sd["Dacl"]
                        if dAcl:
                            for ace in dAcl.aces:
                                obj_data["aces"].append(self.parse_ace(ace))

            self.objects[dn] = obj_data

        # Build children index (one-level)
        for dn, obj in self.objects.items():
            p = dn_parent(dn)
            if p:
                self.children_index[p].append(obj)

        # Sort children nicely
        for p, lst in self.children_index.items():
            lst.sort(key=lambda o: (self._type_order(o), self._obj_name(o).lower()))

        logging.info(f"Loaded {len(self.objects)} objects with ACEs")

    def resolve_identity_to_sid(self, ldapConnection, identity):
        if identity.startswith("S-1-"):
            return identity

        if "," in identity and "=" in identity:
            if identity in self.objects:
                return self.objects[identity].get("sid")
            return None

        try:
            searchFilter = f"(sAMAccountName={identity})"
            resp = ldapConnection.search(
                searchBase=self.baseDN,
                scope=2,
                searchFilter=searchFilter,
                attributes=["objectSid"],
            )
            for item in resp:
                if isinstance(item, ldapasn1.SearchResultEntry):
                    for attr in item["attributes"]:
                        if str(attr["type"]) == "objectSid":
                            sid_bytes = bytes(attr["vals"][0])
                            sid_obj = LDAP_SID(sid_bytes)
                            return sid_obj.formatCanonical()
        except Exception as e:
            logging.error(f"Error resolving identity {identity}: {e}")

        return None

    def _obj_name(self, obj_data):
        display = (obj_data.get("attr") or {}).get("displayName")
        if display:
            return display
        if obj_data.get("samAccountName"):
            return obj_data["samAccountName"]
        return obj_data["dn"].split(",")[0].replace("CN=", "")

    def _get_obj_by_sid(self, sid):
        dn = self.sid_map.get(sid)
        if dn and dn in self.objects:
            return self.objects[dn]
        return {"dn": dn or "", "sid": sid, "aces": [], "objectClass": []}

    def _is_container(self, obj_data) -> bool:
        cls = set(obj_data.get("objectClass", []))
        # conservative: OU/domain/container
        return bool(cls.intersection({"organizationalunit", "domain", "container"}))

    def _is_principal(self, obj_data) -> bool:
        cls = set(obj_data.get("objectClass", []))
        return bool(cls.intersection({"user", "group", "computer"}))

    def _type_order(self, obj_data) -> int:
        cls = set(obj_data.get("objectClass", []))
        if "organizationalunit" in cls:
            return 0
        if "container" in cls or "domain" in cls:
            return 1
        if "group" in cls:
            return 2
        if "user" in cls:
            return 3
        if "computer" in cls:
            return 4
        return 9

    def _icon_type_style(self, obj_data):
        cls = obj_data.get("objectClass", [])
        if self.__no_emoji:
            if "user" in cls:
                return ("U", "USER", "obj.user")
            if "group" in cls:
                return ("G", "GROUP", "obj.group")
            if "computer" in cls:
                return ("C", "COMPUTER", "obj.computer")
            if "organizationalunit" in cls:
                return ("OU", "OU", "obj.ou")
            if "domain" in cls:
                return ("D", "DOMAIN", "obj.domain")
            if "container" in cls:
                return ("CT", "CONTAINER", "obj.container")
            return ("*", "OBJECT", "obj.other")

        if "user" in cls:
            return ("👤", "USER", "obj.user")
        if "group" in cls:
            return ("👥", "GROUP", "obj.group")
        if "computer" in cls:
            return ("💻", "COMPUTER", "obj.computer")
        if "organizationalunit" in cls:
            return ("📁", "OU", "obj.ou")
        if "domain" in cls:
            return ("🌐", "DOMAIN", "obj.domain")
        if "container" in cls:
            return ("🗂️", "CONTAINER", "obj.container")
        return ("◆", "OBJECT", "obj.other")

    def _sort_rights(self, rights):
        def key(r):
            if r in ("GENERIC_ALL", "FULL_CONTROL", "WRITE_DACL", "WRITE_OWNER"):
                return (0, r)
            if r in ("GENERIC_WRITE", "ADS_RIGHT_DS_CONTROL_ACCESS", "ADS_RIGHT_DS_WRITE_PROP", "ADS_RIGHT_DS_SELF"):
                return (1, r)
            if r in ("ADS_RIGHT_DS_CREATE_CHILD", "ADS_RIGHT_DS_DELETE_CHILD", "DELETE"):
                return (2, r)
            return (3, r)

        return sorted(set(rights), key=key)

    def _friendly_suffixes(self, obj_type: str | None, obj_type_name: str | None) -> list[str]:
        if obj_type:
            g = obj_type.lower()
            attr = SCHEMA_OBJECTS.get(g)
            if attr:
                return [attr]
            ext = EXTENDED_RIGHTS.get(g)
            if ext:
                return [ext]
        if obj_type_name:
            return [obj_type_name]
        return []

    def _friendly_rights(self, rights: list[str], obj_type: str | None, obj_type_name: str | None) -> list[str]:
        names = []
        suffixes = self._friendly_suffixes(obj_type, obj_type_name)
        suffix_str = " / ".join(suffixes) if suffixes else ""

        if "GENERIC_ALL" in rights:
            names.append("GenericAll")
            return names
        if "FULL_CONTROL" in rights:
            names.append("FullControl")
        if "GENERIC_WRITE" in rights:
            names.append("GenericWrite")
        if "WRITE_DACL" in rights:
            names.append("WriteDacl")
        if "WRITE_OWNER" in rights:
            names.append("WriteOwner")
        if "DELETE" in rights:
            names.append("Delete")

        if "ADS_RIGHT_DS_WRITE_PROP" in rights:
            names.append("WriteProperty")

        if "ADS_RIGHT_DS_CONTROL_ACCESS" in rights:
            if suffix_str:
                names.append(f"ControlAccess({suffix_str})")
            else:
                names.append("ControlAccess")

        if "ADS_RIGHT_DS_SELF" in rights:
            names.append("Self")
        if "ADS_RIGHT_DS_CREATE_CHILD" in rights:
            names.append("CreateChild")
        if "ADS_RIGHT_DS_DELETE_CHILD" in rights:
            names.append("DeleteChild")
        if "ADS_RIGHT_DS_READ_PROP" in rights:
            names.append("ReadProperty")

        if not names:
            names.extend(rights)

        if suffix_str:
            names = [f"{n} ({suffix_str})" for n in names]

        return names

    def _container_control_from_entries(self, entries: list) -> bool:
        """
        Decide whether to expand children:
        - any ALLOW entry with mask implying write/control/create/delete ownership-ish.
        """
        for e in entries:
            if e["effect"] != "ALLOW":
                continue
            m = e["mask"]
            if (
                mask_has(m, "GENERIC_ALL")
                or mask_has(m, "FULL_CONTROL")
                or mask_has(m, "WRITE_DACL")
                or mask_has(m, "WRITE_OWNER")
                or mask_has(m, "GENERIC_WRITE")
                or mask_has(m, "ADS_RIGHT_DS_CONTROL_ACCESS")
                or mask_has(m, "ADS_RIGHT_DS_WRITE_PROP")
                or mask_has(m, "ADS_RIGHT_DS_SELF")
                or mask_has(m, "ADS_RIGHT_DS_CREATE_CHILD")
                or mask_has(m, "ADS_RIGHT_DS_DELETE_CHILD")
            ):
                return True
        return False

    def edges_from_sid(self, sid):
        merged = {}

        for dn, obj in self.objects.items():
            for ace in obj.get("aces", []):
                if ace.get("sid") != sid:
                    continue

                effect = effect_from_typename(ace.get("typeName"))
                if effect == "DENY" and not self.__include_deny:
                    continue
                if effect == "AUDIT" and not self.__include_audit:
                    continue
                if effect not in ("ALLOW", "DENY", "AUDIT"):
                    continue

                if dn not in merged:
                    merged[dn] = {"target_obj": obj, "target_dn": dn, "entries": {}}

                mask = int(ace.get("mask", 0))
                entry_key = (
                    effect,
                    ace.get("typeName") or "",
                    ace.get("objectTypeName") or "",
                    ace.get("objectType") or "",
                    mask,
                )

                if entry_key not in merged[dn]["entries"]:
                    merged[dn]["entries"][entry_key] = {
                        "effect": effect,
                        "aceType": ace.get("typeName") or "",
                        "objectTypeName": ace.get("objectTypeName"),
                        "objectType": ace.get("objectType"),
                        "mask": mask,
                        "rights": set(),
                        "sev": severity_from_mask(mask),
                    }

                merged[dn]["entries"][entry_key]["rights"].update(ace.get("permissions", []) or [])

        edges = []
        for dn, m in merged.items():
            entries = list(m["entries"].values())

            for e in entries:
                e["rights"] = self._sort_rights(list(e["rights"]))

            entries.sort(
                key=lambda e: (
                    effect_rank(e["effect"]),
                    sev_rank(e["sev"]),
                    e["aceType"],
                    str(e.get("objectTypeName") or ""),
                )
            )

            top_rank = min((sev_rank(e["sev"]) for e in entries), default=9)
            edges.append({"target_obj": m["target_obj"], "target_dn": dn, "entries": entries, "top_rank": top_rank})

        edges.sort(key=lambda e: (e["top_rank"], self._obj_name(e["target_obj"]).lower()))
        return edges


    def _to_obj_ref(self, obj_data):
        extras = []
        if obj_data.get("samAccountName"):
            extras.append(("sAMAccountName", obj_data["samAccountName"]))
        attr = obj_data.get("attr") or {}
        for k in ("displayName", "description"):
            if attr.get(k):
                extras.append((k, attr[k]))
        if obj_data.get("memberOf"):
            extras.append(("memberOf", "\n".join(obj_data["memberOf"])))
        if obj_data.get("objectGUID"):
            extras.append(("objectGUID", obj_data["objectGUID"]))
        parent_dn = dn_parent(obj_data.get("dn", ""))
        if parent_dn:
            extras.append(("Parent DN", parent_dn))

        return renderer_rich.ObjRef(
            dn=obj_data.get("dn", "(unknown DN)"),
            name=self._obj_name(obj_data),
            sid=obj_data.get("sid"),
            classes=tuple(obj_data.get("objectClass", [])),
            extra=tuple(extras),
        )

    def print_tree_rich(self, start_sid):
        if Console is None or renderer_rich is None:
            print("[!] rich is not installed. Install: pip install rich")
            return

        console = Console(theme=renderer_rich.default_theme())

        root_obj = self._get_obj_by_sid(start_sid)
        root_ref = self._to_obj_ref(root_obj)

        limits = renderer_rich.RenderLimits(
            max_depth=self.__max_depth,
            max_targets_per_trustee=self.__max_targets,
            max_children_show=self.__max_children,
            max_child_trustees_expand=self.__max_child_trustees,
        )

        def children_of_dn(dn: str):
            children = self.children_index.get(dn, [])
            return [self._to_obj_ref(c) for c in children]

        def edges_for_trustee(trustee_sid: str):
            trustee_obj = self._get_obj_by_sid(trustee_sid)
            trustee_name = self._obj_name(trustee_obj)
            grouped = []
            for e in self.edges_from_sid(trustee_sid):
                ace_edges = []
                for entry in e["entries"]:
                    raw_objtype = entry.get("objectType") or entry.get("objectTypeName")
                    suffixes = self._friendly_suffixes(entry.get("objectType"), entry.get("objectTypeName"))
                    suffix_str = " / ".join(suffixes) if suffixes else None
                    friendly_rights = self._friendly_rights(entry.get("rights", []) or [], entry.get("objectType"), entry.get("objectTypeName"))

                    ace_edges.append(
                        renderer_rich.AceEdge(
                            source_name=trustee_name,
                            effect=entry["effect"],
                            severity=entry["sev"],
                            mask_hex=f"0x{entry['mask']:08x}",
                            rights=tuple(friendly_rights),
                            object_type=raw_objtype,
                            object_type_name=suffix_str,
                        )
                    )
                grouped.append((self._to_obj_ref(e["target_obj"]), ace_edges))
            return grouped

        def memberships_of_dn(dn: str):
            obj = self.objects.get(dn, {})
            memberships = []
            for m_dn in obj.get("memberOf", []):
                m_obj = self.objects.get(m_dn)
                if m_obj:
                    memberships.append(self._to_obj_ref(m_obj))
                else:
                    memberships.append(
                        renderer_rich.ObjRef(
                            dn=m_dn,
                            name=m_dn.split(",")[0].replace("CN=", ""),
                            sid=None,
                            classes=("group",),
                        )
                    )
            return memberships

        def should_expand_trustee(obj_ref: renderer_rich.ObjRef) -> bool:
            if not obj_ref.sid:
                return False
            if not self.__only_expand_principals:
                return True
            cls = set(obj_ref.classes or [])
            return bool(cls.intersection({"user", "group", "computer"}))

        renderer_rich.render_acl_tree(
            console,
            root_ref,
            get_edges_for_trustee=edges_for_trustee,
            get_children_of_dn=children_of_dn,
            get_memberships_of_dn=memberships_of_dn,
            limits=limits,
            no_emoji=self.__no_emoji,
            should_expand_trustee=should_expand_trustee,
        )


    def run(self):
        try:
            ldapConnection = ldap_login(
                self.__target,
                self.baseDN,
                self.__kdcIP,
                self.__kdcHost,
                self.__doKerberos,
                self.__username,
                self.__password,
                self.__domain,
                self.__lmhash,
                self.__nthash,
                self.__aesKey,
            )
            self.__target = ldapConnection._dstHost

        except ldap.LDAPSessionError as e:
            if str(e).find("strongerAuthRequired") < 0:
                logging.error(f"Cannot authenticate {self.__username}")
                return

        self.load_all_objects(ldapConnection)

        target_sid = self.resolve_identity_to_sid(ldapConnection, self.__search_identity)
        if not target_sid:
            logging.error(f"Identity '{self.__search_identity}' not found or could not be resolved")
            return

        logging.info(f"Searching ACL tree for: {self.__search_identity} (SID: {target_sid})")
        logging.info(f"Maximum depth: {self.__max_depth}")

        self.print_tree_rich(target_sid)


if __name__ == "__main__":
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help=True, description="LDAP ACL graph (Rich, merged, children expansion)")

    parser.add_argument("target", action="store", help="[[domain/]username[:password]]")

    parser.add_argument(
        "-identity",
        required=True,
        action="store",
        metavar="identity",
        help="Identity to search (sAMAccountName, DN, or SID) [REQUIRED]",
    )

    parser.add_argument("-ts", action="store_true", help="Adds timestamp to every logging output")
    parser.add_argument("-debug", action="store_true", help="Turn DEBUG output ON")

    parser.add_argument("--max-depth", type=int, default=6, help="Maximum recursion depth (default: 6)")
    parser.add_argument("--max-targets", type=int, default=30, help="Max targets per trustee shown (0 = no limit)")
    parser.add_argument("--max-children", type=int, default=50, help="Max children listed per container (0 = no limit)")
    parser.add_argument("--max-child-trustees", type=int, default=25, help="Max child SIDs expanded per container (0 = no limit)")

    group = parser.add_argument_group("authentication")
    group.add_argument("-hashes", action="store", metavar="LMHASH:NTHASH", help="NTLM hashes LMHASH:NTHASH")
    group.add_argument("-no-pass", action="store_true", help="don't ask for password (useful for -k)")
    group.add_argument("-k", action="store_true", help="Use Kerberos authentication (ccache).")
    group.add_argument("-aesKey", action="store", metavar="hex key", help="AES key for Kerberos (128/256 bits)")

    group = parser.add_argument_group("connection")
    group.add_argument("-dc-ip", action="store", metavar="ip address", help="IP Address of the domain controller.")
    group.add_argument("-dc-host", action="store", metavar="hostname", help="Hostname of the domain controller to use.")

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

    if Console is None:
        logging.warning("For best output install: pip install rich")

    try:
        executer = AclWalk(username, password, domain, options)
        executer.run()
    except Exception as e:
        logging.debug("Exception:", exc_info=True)
        logging.error(str(e))
