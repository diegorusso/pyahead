// Loaded synchronously before CSS so a saved theme applies before the first paint.
(() => {
  const root = document.documentElement;
  const key = "pyahead-theme";
  try {
    const saved = localStorage.getItem(key);
    if (saved === "light" || saved === "dark") root.dataset.theme = saved;
  } catch {
    // Storage can be blocked; the device setting still works.
  }

  document.addEventListener("DOMContentLoaded", () => {
    const trigger = document.getElementById("theme");
    const menu = document.getElementById("theme-options");
    const choices = menu.querySelectorAll("[data-theme-choice]");
    function updateButton() {
      const current = root.dataset.theme ?? "system";
      const label = current === "system" ? "Auto" : current === "light" ? "Light" : "Dark";
      trigger.title = `Color mode, currently ${label}`;
      trigger.setAttribute("aria-label", trigger.title);
      trigger.querySelector("use").setAttribute("href", `#theme-${current}-icon`);
      for (const choice of choices) {
        choice.setAttribute("aria-pressed", String(choice.dataset.themeChoice === current));
      }
    }
    updateButton();
    trigger.hidden = false;
    menu.addEventListener("beforetoggle", (event) => {
      if (event.newState !== "open") return;
      const bounds = trigger.getBoundingClientRect();
      menu.style.top = `${bounds.bottom + 6}px`;
      menu.style.right = `${document.documentElement.clientWidth - bounds.right}px`;
    });
    window.addEventListener("resize", () => menu.hidePopover());
    for (const choice of choices) {
      choice.addEventListener("click", () => {
        const selected = choice.dataset.themeChoice;
        if (selected === "system") delete root.dataset.theme;
        else root.dataset.theme = selected;
        try {
          if (selected === "system") localStorage.removeItem(key);
          else localStorage.setItem(key, selected);
        } catch {
          // A manual choice still works for this page without storage.
        }
        updateButton();
        menu.hidePopover();
        trigger.focus();
      });
    }
  });
})();
