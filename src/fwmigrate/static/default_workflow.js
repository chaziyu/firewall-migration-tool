document.addEventListener("DOMContentLoaded", () => {
  const defaultWorkflow = document.body.dataset.defaultWorkflow;
  if (!defaultWorkflow) return;

  const defaultTab = document.querySelector(`[data-tab="${defaultWorkflow}"]`);
  if (!defaultTab || defaultTab.getAttribute("aria-selected") === "true") return;

  defaultTab.click();
});
