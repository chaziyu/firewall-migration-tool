/* Apply the saved palette before the first paint, including in the desktop app. */
(() => {
  let preference = null;
  try {
    preference = localStorage.getItem("fwmigrate-theme");
  } catch (_) {
    // Browser privacy settings may disable storage; system preference still works.
  }
  const theme =
    preference === "light" || preference === "dark"
      ? preference
      : window.matchMedia("(prefers-color-scheme: dark)").matches
        ? "dark"
        : "light";
  document.documentElement.dataset.theme = theme;
})();
