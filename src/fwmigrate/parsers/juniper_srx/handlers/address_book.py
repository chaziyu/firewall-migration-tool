"""Handler for Junos address-book, address, and address-set configuration hierarchy."""

from __future__ import annotations

import ipaddress

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.juniper_srx.extraction import (
    sanitize_source_attributes,
    sanitize_tokens,
)
from fwmigrate.parsers.juniper_srx.model import (
    JuniperAddress,
    JuniperAddressBook,
    JuniperAddressSet,
    JuniperAddressSetMember,
    JuniperContextConfig,
    JuniperProvenanceKind,
    JuniperSourceProvenance,
)
from fwmigrate.parsers.juniper_srx.tokenizer import JunosCommand, extract_value_list
from fwmigrate.parsers.juniper_srx.provenance import record_scalar_candidate, record_list_candidate


def handle_address_book_command(cmd: JunosCommand, context: JuniperContextConfig) -> bool:
    """
    Handle address-book commands across:
    1. Global address book: 'set security address-book global ...'
    2. Named address book: 'set security address-book <book_name> ...'
    3. Legacy zone address book: 'set security zones security-zone <zone> address-book ...'
    """
    toks = cmd.tokens
    if len(toks) < 3:
        return False

    if toks[1].lower() != "security":
        return False

    # Check case 3: legacy zone address book
    if len(toks) >= 6 and toks[2].lower() == "zones" and toks[3].lower() == "security-zone":
        zone_name = toks[4]
        if toks[5].lower() == "address-book":
            # Book name can be treated as zone-local book: f"zone_{zone_name}"
            book_name = f"zone_{zone_name}"
            if book_name not in context.address_books:
                context.address_books[book_name] = JuniperAddressBook(
                    name=book_name, attached_zones=[zone_name]
                )
            book = context.address_books[book_name]
            book.provenance = JuniperSourceProvenance(
                kind=JuniperProvenanceKind.INHERITED_GROUP if cmd.source_group else JuniperProvenanceKind.LOCAL,
                context=context.context, group_name=cmd.source_group,
            )
            cmd.consumed = True
            cmd.handler = "address_book"
            return _parse_address_book_body(cmd, toks[6:], book, zone_name=zone_name)
        return False

    # Check cases 1 & 2: security address-book <book_name> ...
    if toks[2].lower() == "address-book":
        if len(toks) < 4:
            return False

        book_name = toks[3]
        cmd.consumed = True
        cmd.handler = "address_book"

        if book_name not in context.address_books:
            context.address_books[book_name] = JuniperAddressBook(name=book_name)
        book = context.address_books[book_name]
        book.provenance = JuniperSourceProvenance(
            kind=JuniperProvenanceKind.INHERITED_GROUP if cmd.source_group else JuniperProvenanceKind.LOCAL,
            context=context.context, group_name=cmd.source_group,
        )

        if len(toks) == 4:
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True

        return _parse_address_book_body(cmd, toks[4:], book, zone_name=None)

    return False


def _parse_address_book_body(
    cmd: JunosCommand,
    body_toks: list[str],
    book: JuniperAddressBook,
    zone_name: str | None,
) -> bool:
    if not body_toks:
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True

    first = body_toks[0].lower()

    if first == "attach" and len(body_toks) >= 3 and body_toks[1].lower() == "zone":
        z_name = body_toks[2]
        if z_name not in book.attached_zones:
            book.attached_zones.append(z_name)
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True

    if first == "description" and len(body_toks) >= 2:
        book.description = body_toks[1]
        record_scalar_candidate(book.field_provenance, book.field_candidate_history, "description", book.description, cmd)
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True

    # Address definition: address <name> ...
    if first == "address" and len(body_toks) >= 2:
        addr_name = body_toks[1]
        if addr_name not in book.addresses:
            book.addresses[addr_name] = JuniperAddress(
                name=addr_name, address_book=book.name, zone=zone_name
            )
        addr = book.addresses[addr_name]
        addr.provenance = book.provenance

        if len(body_toks) == 2:
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True

        sub = body_toks[2].lower()
        if sub == "description" and len(body_toks) >= 4:
            addr.description = body_toks[3]
            record_scalar_candidate(addr.field_provenance, addr.field_candidate_history, "description", addr.description, cmd)
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif sub in ("dns-name", "dns-address") and len(body_toks) >= 4:
            addr.type = "dns-name"
            addr.fqdn = body_toks[3]
            record_scalar_candidate(addr.field_provenance, addr.field_candidate_history, "fqdn", addr.fqdn, cmd)
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif sub == "range-address":
            addr.source_attributes["range_address_source"] = sanitize_source_attributes(
                {"tokens": body_toks[3:], "raw": cmd.raw_sanitized}
            )
            if len(body_toks) != 6 or body_toks[4].lower() != "to":
                cmd.extraction_status = ExtractionStatus.PARSE_ERROR
                cmd.requires_manual_review = True
                cmd.parse_error = f"Malformed range-address; expected '<start> to <end>' in '{cmd.raw_sanitized}'"
                return True
            try:
                start = ipaddress.ip_address(body_toks[3])
                end = ipaddress.ip_address(body_toks[5])
            except ValueError:
                cmd.extraction_status = ExtractionStatus.PARSE_ERROR
                cmd.requires_manual_review = True
                cmd.parse_error = f"Invalid range-address endpoint in '{cmd.raw_sanitized}'"
                return True
            if start.version != end.version:
                cmd.extraction_status = ExtractionStatus.PARSE_ERROR
                cmd.requires_manual_review = True
                cmd.parse_error = f"Mixed address families in range-address '{cmd.raw_sanitized}'"
                return True
            addr.type = "range-address"
            addr.range_start = body_toks[3]
            addr.range_end = body_toks[5]
            record_scalar_candidate(addr.field_provenance, addr.field_candidate_history, "range", (addr.range_start, addr.range_end), cmd)
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif sub == "wildcard-address" and len(body_toks) >= 4:
            addr.type = "wildcard-address"
            addr.wildcard = body_toks[3]
            record_scalar_candidate(addr.field_provenance, addr.field_candidate_history, "wildcard", addr.wildcard, cmd)
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif sub == "ip-prefix" and len(body_toks) >= 4:
            if body_toks[3].upper() == "ACCESS-DENIED" or cmd.access_denied:
                addr.source_attributes["access_denied"] = True
                cmd.extraction_status = ExtractionStatus.UNSUPPORTED
                cmd.requires_manual_review = True
                return True
            addr.type = "ip-prefix"
            addr.prefix = body_toks[3]
            record_scalar_candidate(addr.field_provenance, addr.field_candidate_history, "prefix", addr.prefix, cmd)
            try:
                ipaddress.ip_network(addr.prefix, strict=False)
                cmd.extraction_status = ExtractionStatus.NORMALIZED
            except ValueError:
                cmd.extraction_status = ExtractionStatus.PARSE_ERROR
                cmd.parse_error = f"Invalid IP prefix: {addr.prefix}"
            return True
        else:
            # Direct ip-prefix value: e.g. address NAME 10.0.0.0/24
            val = body_toks[2]
            if val.upper() == "ACCESS-DENIED" or cmd.access_denied:
                addr.source_attributes["access_denied"] = True
                cmd.extraction_status = ExtractionStatus.UNSUPPORTED
                cmd.requires_manual_review = True
                return True
            addr.type = "ip-prefix"
            addr.prefix = val
            record_scalar_candidate(addr.field_provenance, addr.field_candidate_history, "prefix", addr.prefix, cmd)
            try:
                ipaddress.ip_network(val, strict=False)
                cmd.extraction_status = ExtractionStatus.NORMALIZED
            except ValueError:
                cmd.extraction_status = ExtractionStatus.PARSE_ERROR
                cmd.parse_error = f"Invalid IP prefix: {val}"
            return True

    # Address-set definition: address-set <set_name> ...
    if first == "address-set" and len(body_toks) >= 2:
        set_name = body_toks[1]
        if set_name not in book.address_sets:
            book.address_sets[set_name] = JuniperAddressSet(
                name=set_name, address_book=book.name, zone=zone_name
            )
        aset = book.address_sets[set_name]
        aset.provenance = book.provenance

        if len(body_toks) == 2:
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True

        sub = body_toks[2].lower()
        if sub == "description" and len(body_toks) >= 4:
            aset.description = body_toks[3]
            record_scalar_candidate(aset.field_provenance, aset.field_candidate_history, "description", aset.description, cmd)
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif sub == "address" and len(body_toks) >= 4:
            members = extract_value_list(body_toks[3:])
            for m in members:
                if not any(mem.name == m and mem.member_type == "address" for mem in aset.members):
                    aset.members.append(JuniperAddressSetMember(name=m, member_type="address", source_path=cmd.raw_sanitized))
                record_list_candidate(aset.member_candidate_history, "address", m, cmd)
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif sub == "address-set" and len(body_toks) >= 4:
            members = extract_value_list(body_toks[3:])
            for m in members:
                if not any(mem.name == m and mem.member_type == "address-set" for mem in aset.members):
                    aset.members.append(JuniperAddressSetMember(name=m, member_type="address-set", source_path=cmd.raw_sanitized))
                record_list_candidate(aset.member_candidate_history, "address-set", m, cmd)
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True

        safe_body_toks = sanitize_tokens(body_toks)
        attr_key = "_".join(safe_body_toks[2:])
        aset.source_attributes[attr_key] = sanitize_source_attributes({"raw": cmd.raw_sanitized})
        cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
        return True

    # Other address-book level attributes
    safe_body_toks = sanitize_tokens(body_toks)
    attr_key = "_".join(safe_body_toks)
    book.source_attributes[attr_key] = sanitize_source_attributes({"raw": cmd.raw_sanitized})
    cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
    return True
