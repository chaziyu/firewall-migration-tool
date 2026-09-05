"""Reference and dependency resolver for Junos SRX configuration objects."""

from __future__ import annotations

from typing import Dict, List, Optional, Set, Tuple

from pydantic import BaseModel, Field

from fwmigrate.parsers.juniper_srx.model import (
    JuniperAddress,
    JuniperAddressBook,
    JuniperAddressSet,
    JuniperApplication,
    JuniperApplicationSet,
    JuniperContextConfig,
)
from fwmigrate.parsers.juniper_srx.provenance import is_effective_candidate


class ResolvedAddressReference(BaseModel):
    name: str
    original_name: str
    address_book: str
    is_group: bool = False
    is_builtin_any: bool = False
    builtin_type: Optional[str] = None  # "any", "any-ipv4", "any-ipv6"
    address: Optional[JuniperAddress] = None
    address_set: Optional[JuniperAddressSet] = None
    resolved_members: List[str] = Field(default_factory=list)
    has_cycle: bool = False
    is_unresolved: bool = False


BUILTIN_ADDRESS_KEYWORDS = {
    "any": "any",
    "any-ipv4": "any-ipv4",
    "any-ipv6": "any-ipv6",
}

PREDEFINED_APPLICATIONS = {
    "junos-any", "junos-ftp", "junos-http", "junos-https", "junos-icmp-all",
    "junos-ssh", "junos-telnet", "junos-dns-udp", "junos-dns-tcp",
}

PREDEFINED_APPLICATIONS = {
    "junos-any", "junos-ftp", "junos-http", "junos-https", "junos-icmp-all",
    "junos-ssh", "junos-telnet", "junos-dns-udp", "junos-dns-tcp",
}


class JuniperReferenceResolver:
    """Resolves cross-object references according to Junos scope and hierarchy rules."""

    def __init__(self, context: JuniperContextConfig) -> None:
        self.context = context
        # Precompute zone -> address book attachment map
        self.zone_to_book: Dict[str, str] = {}
        for book_name, book in self.context.address_books.items():
            for z in book.attached_zones:
                self.zone_to_book[z] = book_name

    def resolve_policy_source(
        self, from_zone: Optional[str], reference: str
    ) -> ResolvedAddressReference:
        """Resolve address reference in source of a policy scoped to a zone."""
        return self._resolve_address_in_zone(from_zone, reference)

    def resolve_policy_destination(
        self, to_zone: Optional[str], reference: str
    ) -> ResolvedAddressReference:
        """Resolve address reference in destination of a policy scoped to a zone."""
        return self._resolve_address_in_zone(to_zone, reference)

    def resolve_global_policy(self, reference: str) -> ResolvedAddressReference:
        """Global policies resolve address references strictly against the global address book."""
        return self._resolve_in_book("global", reference)

    def resolve_nat(self, reference: str) -> ResolvedAddressReference:
        """Junos NAT rule address-name references resolve strictly against the global address book."""
        return self._resolve_in_book("global", reference)

    def _resolve_address_in_zone(
        self, zone: Optional[str], reference: str
    ) -> ResolvedAddressReference:
        ref_lower = reference.lower()
        if ref_lower in BUILTIN_ADDRESS_KEYWORDS:
            return ResolvedAddressReference(
                name=reference,
                original_name=reference,
                address_book="global",
                is_builtin_any=True,
                builtin_type=ref_lower,
            )

        # 1. Search attached/zone book if zone is known
        if zone:
            # Check attached book
            attached_book_name = self.zone_to_book.get(zone)
            if zone in self.context.zones and attached_book_name and attached_book_name in self.context.address_books:
                res = self._resolve_in_book(attached_book_name, reference)
                if not res.is_unresolved:
                    return res

            # Check legacy zone-local book: f"zone_{zone}"
            legacy_book_name = f"zone_{zone}"
            if legacy_book_name in self.context.address_books:
                res = self._resolve_in_book(legacy_book_name, reference)
                if not res.is_unresolved:
                    return res

        # 2. Fallback to global address book
        if "global" in self.context.address_books:
            res = self._resolve_in_book("global", reference)
            if not res.is_unresolved:
                return res

        # If not in zone-attached book or global book, address is unresolved in this zone scope
        return ResolvedAddressReference(
            name=reference,
            original_name=reference,
            address_book="unknown",
            is_unresolved=True,
        )

    def _resolve_in_book(
        self, book_name: str, reference: str
    ) -> ResolvedAddressReference:
        ref_lower = reference.lower()
        if ref_lower in BUILTIN_ADDRESS_KEYWORDS:
            return ResolvedAddressReference(
                name=reference,
                original_name=reference,
                address_book=book_name,
                is_builtin_any=True,
                builtin_type=ref_lower,
            )

        book = self.context.address_books.get(book_name)
        if not book:
            return ResolvedAddressReference(
                name=reference,
                original_name=reference,
                address_book=book_name,
                is_unresolved=True,
            )

        # Canonical name handling: prefix context if non-root, and book name if non-global book
        if self.context.name != "root":
            canonical_name = (
                f"{self.context.name}__{reference}"
                if book_name == "global"
                else f"{self.context.name}__{book_name}__{reference}"
            )
        else:
            canonical_name = (
                reference if book_name == "global" else f"{book_name}__{reference}"
            )

        # Check address object
        if reference in book.addresses and self._object_is_effective(book.addresses[reference]):
            return ResolvedAddressReference(
                name=canonical_name,
                original_name=reference,
                address_book=book_name,
                is_group=False,
                address=book.addresses[reference],
            )

        # Check address-set
        if reference in book.address_sets and self._object_is_effective(book.address_sets[reference]):
            aset = book.address_sets[reference]
            members, has_cycle = self.expand_address_set(book, reference)
            return ResolvedAddressReference(
                name=canonical_name,
                original_name=reference,
                address_book=book_name,
                is_group=True,
                address_set=aset,
                resolved_members=members,
                has_cycle=has_cycle,
            )

        return ResolvedAddressReference(
            name=reference,
            original_name=reference,
            address_book=book_name,
            is_unresolved=True,
        )

    def expand_address_set(
        self, book: JuniperAddressBook, set_name: str
    ) -> Tuple[List[str], bool]:
        """
        Recursively expand nested address sets with cycle detection.
        Returns (list of member names, has_cycle boolean).
        """
        visited_sets: Set[str] = set()
        resolved_members: List[str] = []
        has_cycle = False

        def _dfs(current_set_name: str) -> None:
            nonlocal has_cycle
            if current_set_name in visited_sets:
                has_cycle = True
                return
            visited_sets.add(current_set_name)

            aset = book.address_sets.get(current_set_name)
            if not aset:
                return

            for m in aset.members:
                if m.disabled or not self._object_is_effective(m):
                    continue
                if m.member_type == "address":
                    # Canonical member name
                    if self.context.name != "root":
                        m_canonical = (
                            f"{self.context.name}__{m.name}"
                            if book.name == "global"
                            else f"{self.context.name}__{book.name}__{m.name}"
                        )
                    else:
                        m_canonical = (
                            m.name if book.name == "global" else f"{book.name}__{m.name}"
                        )
                    if m_canonical not in resolved_members:
                        resolved_members.append(m_canonical)
                elif m.member_type == "address-set":
                    _dfs(m.name)

        _dfs(set_name)
        return resolved_members, has_cycle

    def resolve_application(self, reference: str) -> Tuple[bool, bool, Optional[str]]:
        """
        Check if application/application-set reference exists.
        Returns (is_app, is_app_set, canonical_name).
        """
        if reference.lower() in ("any", "junos-any"):
            return False, False, "any"

        if reference.lower() in PREDEFINED_APPLICATIONS:
            return True, False, reference

        if reference.lower() in PREDEFINED_APPLICATIONS:
            return True, False, reference

        ctx_prefix = f"{self.context.name}__" if self.context.name != "root" else ""

        if reference in self.context.applications and self._object_is_effective(self.context.applications[reference]):
            return True, False, f"{ctx_prefix}{reference}"

        if reference in self.context.application_sets and self._object_is_effective(self.context.application_sets[reference]):
            return False, True, f"{ctx_prefix}{reference}"

        return False, False, None

    @staticmethod
    def _object_is_effective(obj) -> bool:
        """Reject an object only when its recorded candidates are all non-effective."""
        candidates = [c for values in obj.field_candidate_history.values() for c in values]
        return not candidates or any(is_effective_candidate(c) for c in candidates)

    def resolve_named_reference(self, reference: str, collection: dict) -> Optional[str]:
        """Resolve a typed source-profile reference without inventing a target object."""
        if reference in collection:
            return f"{self.context.name}__{reference}" if self.context.name != "root" else reference
        return None

    def resolve_reth_cluster(self, interface_name: str) -> Dict[str, Optional[str]]:
        """Resolve physical interface -> reth -> redundancy group without guessing."""
        physical = self.context.interfaces.get(interface_name)
        reth_name = physical.redundant_parent if physical else None
        reth = self.context.interfaces.get(reth_name) if reth_name else None
        return {
            "physical_interface": interface_name,
            "reth_interface": reth_name,
            "redundancy_group": reth.redundancy_group if reth else None,
        }
