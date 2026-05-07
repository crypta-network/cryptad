(function () {
  "use strict";

  const version = "1";

  function definePermissionSummary() {
    if (!("customElements" in window) || customElements.get("crypta-permission-summary")) {
      return;
    }
    customElements.define(
      "crypta-permission-summary",
      class extends HTMLElement {
        connectedCallback() {
          this.classList.add("cr-permission-summary");
          if (!this.hasAttribute("role")) {
            this.setAttribute("role", "note");
          }
        }
      },
    );
  }

  definePermissionSummary();
  window.CryptaUi = Object.freeze({ version });
})();
