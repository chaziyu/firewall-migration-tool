# Cisco Secure Firewall / FMC REST extraction

Cisco FTD policy extraction is intentionally separate from ASA/LINA CLI parsing.
Access Control Policy, NAT, and referenced policy objects are accepted from an
offline bundle assembled from Cisco Secure Firewall Management Center REST API
responses.

## Bundle format

The parser accepts JSON with `format` set to `cisco-fmc-rest-export-v1` and
`source` set to `fmc-rest-api`.

```json
{
  "format": "cisco-fmc-rest-export-v1",
  "source": "fmc-rest-api",
  "domain": {"id": "<domain UUID>", "name": "Global"},
  "objects": {
    "hosts": {"items": []},
    "networks": {"items": []},
    "ranges": {"items": []},
    "networkgroups": {"items": []},
    "protocolportobjects": {"items": []},
    "portobjectgroups": {"items": []},
    "securityzones": {"items": []},
    "applications": {"items": []},
    "users": {"items": []}
  },
  "access_policies": [
    {
      "id": "<ACP UUID>",
      "name": "Policy",
      "rules": {"items": []},
      "defaultAction": {}
    }
  ],
  "nat_policies": [
    {
      "id": "<NAT policy UUID>",
      "name": "NAT",
      "manual_rules_before_auto": {"items": []},
      "auto_rules": {"items": []},
      "manual_rules_after_auto": {"items": []}
    }
  ]
}
```

Arrays may be supplied directly instead of an `{ "items": [...] }` envelope.
The bundle is an offline interchange container; the objects inside it retain the
FMC REST response fields so source provenance remains available.

## Cisco REST resources represented

The adapter is designed around the documented FMC configuration resources:

- Access Control Rules under `policy/accesspolicies/{containerUUID}/accessrules`
- FTD Manual NAT Rules under `policy/ftdnatpolicies/{containerUUID}/manualnatrules`
- FTD Auto NAT Rules under `policy/ftdnatpolicies/{containerUUID}/autonatrules`
- Hosts, networks, ranges, network groups, protocol/port objects, port object
  groups, security zones, applications, and users referenced by those rules

Collectors must follow FMC pagination and include every referenced object needed
for resolution. An unresolved object UUID/name is never converted to `any`; it is
retained as an unresolved reference, marks the affected item for review, and
blocks generation safety.

## Semantics and safety

- ACP source/destination zones, source/destination networks, destination service,
  applications, users, enabled state, action, and rule logging are normalized.
- `ALLOW` and `BLOCK` map to portable allow/deny actions. `TRUST`, `BLOCK_RESET`,
  inspection/file policy references, and unsupported action variants remain
  explicit and require target capability review.
- Dynamic address-only NAT uses canonical `NATTranslationMode.DYNAMIC_IP`; it is
  distinct from `DYNAMIC_IP_AND_PORT` (PAT).
- Interface-address PAT uses `INTERFACE_ADDRESS`.
- NAT port translation, PAT options, and FMC-only rule options are retained in
  source attributes and trigger manual review when the canonical target-neutral
  model cannot express them losslessly.
- ASA/LINA CLI is never used to infer FMC ACP or NAT policy semantics.
