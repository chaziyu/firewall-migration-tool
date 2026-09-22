Recommended Palo Alto roadmap
1. Fix source structure first
   - Split palo_alto/native.py.
   - Add an XML loader/context walker that carries real ancestor identities.
   - Correctly model device → vsys, shared, device-group hierarchy, managed-device serial, and pre/local/post rulebase position.
   - Do not calculate Panorama inheritance yet.
2. Replace generic records with typed source models
   - Create palo_alto/model/ similar in responsibility to FortiGate:
     address.py, service.py, schedule.py, policy.py, interface.py, nat.py, routing.py, source.py.
   - Give models raw_extra and explicit-source tracking.
   - Keep PANSourceRecord only as Source Inventory, not the primary data model.
   - Missing field must remain “not explicitly configured”, not a PAN-OS default.
3. Create domain extractors
   - Add palo_alto/extraction/.
   - First implement existing fixture coverage in this order:
     addresses/groups → services/groups → schedules → policies → interfaces → NAT → routes.
   - Parse nested XML structurally instead of flattening it.
   - A PAN-OS path/schema registry would be useful as the XML equivalent of FortiGate's section_registry.py.
4. Add relationships + derived views
   - Scoped reference resolution.
   - Shared/device-group/VSYS lookup and shadowing.
   - Device-group parent relationships.
   - Interface/import topology.
   - Policy ordering across pre/local/post rulebases.
   - NAT normalization only as a derived view.
   - Keep source state immutable.
5. Validation and reporting last
   - Validate duplicates, unresolved references, malformed IP/port/range values, missing policy fields, scope collisions, NAT references, etc.
   - Replace export/excel.py substring heuristics with typed sheets/schema.
   - Retain Source Inventory, unknown settings, and validation sheets.
   - Turn the existing rich tests/fixtures/palo_alto/*.xml files into real semantic regression tests.
Target architecture
PAN-OS XML
→ XML Loader / Structural Context
→ Typed Extractors
→ PANOSConfig
→ Relationships / Transforms
→ PANOSDerivedViews
→ Validation
→ Excel / Web
I would not add a tokenizer or command evaluator to Palo Alto. Those exist in FortiGate because FortiOS CLI requires them. The part to copy is the separation of responsibilities and typed source-state design, not the syntax-processing implementation.