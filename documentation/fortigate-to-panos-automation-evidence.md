# FortiGate to PAN-OS automation evidence

The renderer targets PAN-OS 11.1. A hardware model is optional. No model,
including PA-820, is inferred from the firmware version. Explicit interface
mappings remain engineer decisions. Hardware capacity, available ports and
licenses require separate evidence before operational acceptance.

## FortiOS 7.2.13 effective values

Authority: [FortiOS 7.2.13 CLI Reference](https://fortinetweb.s3.amazonaws.com/docs.fortinet.com/v2/attachments/9b85aed5-fafc-11f0-8b43-d2943efe5b2f/FortiOS-7.2.13-CLI_Reference.pdf).
The following PDF pages were inspected during implementation:

- IPv4 address type: ipmask, page 355. Omitted IPv4 subnet: 0.0.0.0 0.0.0.0, page 354.
- IP pool type: overload, page 403.
- VIP port-forward protocol: TCP, page 572.
- Policy source NAT: disabled, page 435. Policy status: enabled, page 441.
- DHCP server status and type: enabled and regular, page 1238.
- DHCP IP allocation mode and lease: range and 604800 seconds, page 1237.
- DHCP DNS service: specify, page 1236.

These values are derived only when source metadata identifies exactly 7.2.13.
Explicit values take precedence. IPv6 addresses do not receive IPv4 defaults.
The explicit vendor configuration remains unchanged. The report retains each
derived value's version and reference. Unknown versions remain unresolved.

Interface association restricts which source policy interface can select an
address. The converter checks explicit direct and nested policy consumers before
accepting a named association. Missing interfaces, ambiguous/cyclic membership
and mismatched policy interfaces retain the block. See the official
[Fortinet interface-association explanation](https://community.fortinet.com/fortigate-3/troubleshooting-tip-unable-to-select-address-object-in-policy-94143).
Routing eligibility is distinct from an actual route; enabling it creates no
target route. Route planning remains independently validated.

## Executable expansions

- IPv4 and IPv6 objects retain distinct identities and reference bindings.
- A static interface-subnet address requires an explicit IPv4 prefix, a unique
  source interface and approved target mapping. Its interface dependency must
  be satisfied before the address can render.
- Management profile reuse requires the selected device's complete explicit
  protocols and permitted networks. Unknown settings, omitted toggles,
  inherited scope and ambiguous matches prevent exact reuse. Missing profile
  inventory does not imply an empty namespace.
- Combined static VIP and pool SNAT supports a complete set of up to 256
  isolated policy partitions. Each requires one explicit IPv4 client subnet,
  one VIP, a supported pool translation, identical source matching and an
  always/ALL policy. Shared public addresses, shared mapped servers, extra
  policies, uncertain port/identity/time matches and mapped-server client
  sources retain the manual-design block. No generic NAT equivalence is claimed.
- IKE crypto profiles can retain an ordered list of supported DH groups for a
  single supported encryption/authentication proposal. IPsec PFS remains a
  single target group. Multiple ordered proposal pairs remain blocked to avoid
  creating additional encryption/authentication combinations. See
  [PAN IKE crypto profiles](https://docs.paloaltonetworks.com/network-security/ipsec-vpn/administration/set-up-site-to-site-vpn/define-cryptographic-profiles/define-ike-crypto-profiles).

## Unchanged evidence and equivalence gates

This is partial support. VIP-aware policy priority, arbitrary combined NAT,
non-TCP/UDP application selectors, route-priority/ECMP equivalence, overnight
schedule/timezone conversion, security-profile/decryption crosswalks,
authenticated VPN structures, identity provisioning, dynamic feeds,
GlobalProtect replacement, load balancing and per-IP shaping are not made
executable by removing warnings. Their implementation and acceptance still need
the corresponding proof, source/target evidence or approved replacement design.

The supplied example still has a malformed WAN primary address and missing
interface evidence. Credentials cannot be recovered from sanitized source.
Neither command generation nor passing local tests proves live behavior.
Candidate validation and explicit commit remain separate existing operations.
