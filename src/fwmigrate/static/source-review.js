/* Presentation only: all inventory and policy values come from /api/preview. */
window.SourceReview = class SourceReview {
  constructor() {
    this.policies = [];
    this.search = document.getElementById("policy-search");
    this.filter = document.getElementById("policy-filter");
    this.body = document.getElementById("policy-table-body");
    this.search.addEventListener("input", () => this.renderPolicies());
    this.filter.addEventListener("change", () => this.renderPolicies());
  }

  reset() {
    this.policies = [];
    this.search.value = "";
    this.filter.value = "all";
    this.body.replaceChildren();
    document.getElementById("policy-review").open = false;
    document.getElementById("review-findings").replaceChildren();
  }

  render(data) {
    const count = (value) => Math.max(0, Number(value) || 0);
    const stats = data.stats || {};
    const optimization = data.optimization || {};
    this.policies = Array.isArray(data.policies) ? data.policies.slice(0, 50) : [];
    document.getElementById("review-inventory-detail").textContent =
      `${count(stats.interfaces)} interfaces · ${count(stats.zones)} zones · ${count(stats.nat_rules)} NAT rules · ${count(stats.routes)} routes`;
    const findings = document.getElementById("review-findings");
    findings.replaceChildren();
    const unused = count(optimization.unused_addresses_count) + count(optimization.unused_services_count);
    const shadowed = count(optimization.shadowed_rules_count);
    const duplicateGroups = count(optimization.duplicate_address_groups_count);
    const messages = [];
    if (shadowed) messages.push(`${shadowed} potentially shadowed ${shadowed === 1 ? "rule" : "rules"}. Review policy order and overlap before migration.`);
    if (unused) messages.push(`${unused} unused address or service ${unused === 1 ? "object" : "objects"}. Check the pruning option before generating a bundle.`);
    if (duplicateGroups) messages.push(`${duplicateGroups} ${duplicateGroups === 1 ? "set" : "sets"} of duplicate address objects detected.`);
    if (!messages.length) messages.push("No unused objects, duplicate addresses, or shadowed rules reported by these checks. Target compatibility still requires review.");
    findings.dataset.state = shadowed || unused || duplicateGroups ? "attention" : "info";
    messages.forEach((message) => {
      const paragraph = document.createElement("p");
      paragraph.textContent = message;
      findings.appendChild(paragraph);
    });
    document.getElementById("policy-preview-count").textContent = `(${this.policies.length})`;
    document.getElementById("policy-preview-scope").textContent =
      `Preview contains ${this.policies.length} of ${count(stats.policies)} parsed policies (up to the first 50). Filters search this preview only. Download Excel for the full parsed inventory.`;
    this.renderPolicies();
  }

  renderPolicies() {
    const query = this.search.value.trim().toLowerCase();
    const filter = this.filter.value;
    const display = (value) => value === "<IR_ANY>" ? "Any" : String(value ?? "");
    const list = (value) => Array.isArray(value) ? value.map(display).join(", ") : display(value);
    const policies = this.policies.filter((policy) => {
      const matchesAction = filter === "all" || (filter === "disabled" ? policy.disabled : policy.action === filter);
      const text = [policy.id, policy.action, policy.from_zone, policy.to_zone, policy.source, policy.destination, policy.service, policy.description, policy.disabled ? "disabled" : "enabled"].map(list).join(" ").toLowerCase();
      return matchesAction && text.includes(query);
    });
    const rows = document.createDocumentFragment();
    policies.forEach((policy) => {
      const row = document.createElement("tr");
      const cell = (text, className = "") => {
        const td = document.createElement("td");
        td.textContent = text;
        if (className) td.className = className;
        row.appendChild(td);
        return td;
      };
      const name = cell(`${policy.index ?? "—"}. ${policy.id || "Unnamed policy"}`, "policy-name");
      const state = document.createElement("small");
      state.textContent = policy.disabled ? "Disabled" : "Enabled";
      name.appendChild(state);
      const action = cell(policy.action || "Not reported", "policy-action");
      action.dataset.action = policy.action === "allow" || policy.action === "deny" ? policy.action : "other";
      cell(`${list(policy.from_zone) || "Not reported"} → ${list(policy.to_zone) || "Not reported"}`);
      cell(list(policy.source) || "Not reported", "policy-value");
      cell(list(policy.destination) || "Not reported", "policy-value");
      cell(list(policy.service) || "Not reported", "policy-value");
      rows.appendChild(row);
    });
    this.body.replaceChildren(rows);
    document.getElementById("policy-filter-result").textContent = `${policies.length} of ${this.policies.length} previewed policies shown`;
    const empty = document.getElementById("policy-empty");
    empty.classList.toggle("hidden", policies.length > 0);
    empty.textContent = this.policies.length ? "No policies match these filters. Change the search or policy filter." : "The source preview returned no security policies. Review the Excel inventory and extraction warnings.";
    document.querySelector(".policy-table-scroll").classList.toggle("hidden", policies.length === 0);
  }
};
