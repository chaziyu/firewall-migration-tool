const compactSidebarStylesheet = document.createElement("link");
compactSidebarStylesheet.rel = "stylesheet";
compactSidebarStylesheet.href = "/static/sidebar_compact.css?v=1.1";
compactSidebarStylesheet.dataset.workspaceStyle = "sidebar-compact";
document.head.appendChild(compactSidebarStylesheet);

document.addEventListener("DOMContentLoaded", () => {
  const modeTabs = document.querySelector(".mode-tabs");
  if (modeTabs) {
    modeTabs.addEventListener(
      "keydown",
      (event) => {
        const navigationKeys = [
          "ArrowLeft",
          "ArrowRight",
          "ArrowUp",
          "ArrowDown",
          "Home",
          "End",
        ];
        if (!navigationKeys.includes(event.key)) return;

        const tabs = [...modeTabs.querySelectorAll('[role="tab"]')].filter(
          (tab) => !tab.disabled,
        );
        const current = tabs.indexOf(event.target.closest('[role="tab"]'));
        if (current < 0) return;

        event.preventDefault();
        event.stopImmediatePropagation();

        const nextIndex =
          event.key === "Home"
            ? 0
            : event.key === "End"
              ? tabs.length - 1
              : (current +
                  (["ArrowRight", "ArrowDown"].includes(event.key) ? 1 : -1) +
                  tabs.length) %
                tabs.length;
        tabs[nextIndex].focus();
        tabs[nextIndex].click();
      },
      true,
    );
  }

  const defaultWorkflow = document.body.dataset.defaultWorkflow;
  if (!defaultWorkflow) return;

  const defaultTab = document.querySelector(`[data-tab="${defaultWorkflow}"]`);
  if (!defaultTab || defaultTab.getAttribute("aria-selected") === "true") return;

  defaultTab.click();
});
