(function () {
  "use strict";

  const appId = "publisher";
  const defaultCompatibilityMode = "COMPAT_CURRENT";
  const state = {
    uploadQueueReversed: false,
    uploadQueueSortBy: null,
  };

  const elements = {
    fileForm: document.getElementById("file-form"),
    directoryForm: document.getElementById("directory-form"),
    result: document.getElementById("result"),
    status: document.getElementById("status"),
    uploadQueueButton: document.getElementById("upload-queue-button"),
  };

  document.addEventListener("DOMContentLoaded", start);

  async function start() {
    bindControls();
    try {
      await CryptaPlatform.bootstrap.load({ appId });
      initializeForm(elements.fileForm);
      initializeForm(elements.directoryForm);
    } catch (error) {
      setStatus(CryptaPlatform.api.errorMessage(error), "error");
    }
  }

  function bindControls() {
    elements.fileForm.addEventListener("submit", submitInsert);
    elements.directoryForm.addEventListener("submit", submitInsert);
    elements.uploadQueueButton.addEventListener("click", showUploadQueue);
    elements.result.addEventListener("click", interceptQueueClick);
    elements.result.addEventListener("submit", interceptQueueSubmit);
  }

  function initializeForm(form) {
    const sourceType = sourceTypeFor(form);
    const identifier = form.querySelector('input[name="identifier"]');
    if (identifier instanceof HTMLInputElement && !identifier.value.trim()) {
      identifier.value = generatedIdentifier(sourceType);
    }
    const compatibility = form.querySelector('input[name="compatibilityMode"]');
    if (compatibility instanceof HTMLInputElement && !compatibility.value.trim()) {
      compatibility.value = defaultCompatibilityMode;
    }
  }

  async function submitInsert(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const sourceType = sourceTypeFor(form);
    const insert =
      sourceType === "directory"
        ? CryptaPlatform.content.insertDirectory
        : CryptaPlatform.content.insertFile;
    try {
      const result = await insert(buildInsertFormData(form));
      setStatus("Insert queued.", "success");
      renderInsertResult(result);
      form.reset();
      initializeForm(form);
    } catch (error) {
      setStatus(CryptaPlatform.api.errorMessage(error), "error");
    }
  }

  function buildInsertFormData(form) {
    const body = new FormData();
    const sourceType = sourceTypeFor(form);
    const identifierField = form.querySelector('input[name="identifier"]');
    const identifier = fieldValue(form, "identifier") || generatedIdentifier(sourceType);
    if (identifierField instanceof HTMLInputElement) {
      identifierField.value = identifier;
    }

    body.set("sourcePath", fieldValue(form, "sourcePath"));
    body.set("insertUri", fieldValue(form, "insertUri"));
    body.set("identifier", identifier);
    body.set("compatibilityMode", fieldValue(form, "compatibilityMode") || defaultCompatibilityMode);

    const compress = form.querySelector('input[name="compress"]');
    if (compress instanceof HTMLInputElement && compress.checked) {
      body.set("compress", "on");
    }

    const contentType = fieldValue(form, "contentType");
    if (contentType) {
      body.set("contentType", contentType);
    }
    const targetFilename = fieldValue(form, "targetFilename");
    if (targetFilename) {
      body.set("targetFilename", targetFilename);
    }
    return body;
  }

  async function showUploadQueue() {
    try {
      setStatus("Loading upload queue...");
      const snapshot = await CryptaPlatform.queue.snapshot({
        page: "uploads",
        sortBy: state.uploadQueueSortBy,
        reversed: state.uploadQueueReversed,
      });
      renderQueue(snapshot.contentHtml);
      setStatus(uploadQueueStatusMessage());
    } catch (error) {
      setStatus(CryptaPlatform.api.errorMessage(error), "error");
    }
  }

  function renderInsertResult(data) {
    const panel = document.createElement("div");
    panel.className = "summary";
    panel.append(
      summaryRow("Operation", data.operation),
      summaryRow("Source type", data.sourceType),
      summaryRow("Source path", data.sourcePath),
      summaryRow("Insert URI", data.insertUri),
      summaryRow("Identifier", data.identifier),
      summaryRow("Outcome", data.outcome),
    );
    const button = document.createElement("button");
    button.className = "cr-button cr-button--secondary";
    button.type = "button";
    button.textContent = "Show upload queue";
    button.addEventListener("click", showUploadQueue);
    elements.result.replaceChildren(panel, button);
  }

  function renderQueue(contentHtml) {
    const container = document.createElement("div");
    container.className = "legacy-fragment";
    if (typeof contentHtml !== "string" || !contentHtml) {
      container.append(text("p", "cr-empty", "No upload queue content was returned."));
      elements.result.replaceChildren(container);
      return;
    }
    container.replaceChildren(CryptaPlatform.dom.sanitizeFragment(contentHtml));
    elements.result.replaceChildren(container);
  }

  function interceptQueueClick(event) {
    const target = event.target instanceof Element ? event.target : null;
    const anchor = target ? target.closest("a") : null;
    if (anchor && elements.result.contains(anchor)) {
      interceptQueueAnchor(event, anchor);
    }
  }

  function interceptQueueAnchor(event, anchor) {
    if (
      event.defaultPrevented ||
      event.button !== 0 ||
      event.metaKey ||
      event.ctrlKey ||
      event.shiftKey ||
      event.altKey
    ) {
      return false;
    }

    const href = anchor.getAttribute("href") || "";
    if (isUploadQueueKeyListLink(href)) {
      event.preventDefault();
      exportUploadQueueKeys();
      return true;
    }
    if (updateUploadQueueSort(href)) {
      event.preventDefault();
      return true;
    }
    return false;
  }

  function interceptQueueSubmit(event) {
    const form = event.target;
    if (!(form instanceof HTMLFormElement)) {
      return;
    }
    const submitter = event.submitter || form.querySelector("button, input[type='submit']");
    event.preventDefault();
    setStatus(unsupportedQueueAction(submitter && submitter.name), "error");
  }

  function unsupportedQueueAction(submitterName) {
    const action = typeof submitterName === "string" ? submitterName.replaceAll("_", " ") : "";
    if (!action) {
      return "Queue actions are handled in Queue Manager.";
    }
    return `Queue action "${action}" is handled in Queue Manager.`;
  }

  async function exportUploadQueueKeys() {
    setStatus("Preparing upload key list...");
    try {
      const url = CryptaPlatform.api.url("queue/keys");
      url.searchParams.set("page", "uploads");
      const data = await CryptaPlatform.api.get(url);
      const keys = Array.isArray(data.keys)
        ? data.keys.filter((value) => typeof value === "string")
        : [];
      const textBody = keys.length === 0 ? "" : `${keys.join("\n")}\n`;
      downloadTextFile("uploads-keys.txt", textBody);
      setStatus(`Exported ${keys.length} upload queue keys.`, "success");
    } catch (error) {
      setStatus(CryptaPlatform.api.errorMessage(error), "error");
    }
  }

  function updateUploadQueueSort(rawHref) {
    if (typeof rawHref !== "string" || !rawHref.startsWith("?")) {
      return false;
    }
    const params = new URLSearchParams(rawHref.slice(1));
    if (!params.has("sortBy")) {
      return false;
    }
    state.uploadQueueSortBy = params.get("sortBy");
    state.uploadQueueReversed = params.get("reversed") === "true" || params.has("reversed");
    showUploadQueue();
    return true;
  }

  function isUploadQueueKeyListLink(rawHref) {
    const href = typeof rawHref === "string" ? rawHref.trim() : "";
    if (href === "listKeys.txt") {
      return true;
    }
    if (!href || href.startsWith("?") || href.startsWith("#") || href.startsWith("//")) {
      return false;
    }
    try {
      const url = new URL(href, window.location.href);
      return CryptaPlatform.dom.sameOrigin(url.href) && url.pathname === "/uploads/listKeys.txt";
    } catch (error) {
      return false;
    }
  }

  function downloadTextFile(filename, body) {
    const blob = new Blob([body], { type: "text/plain;charset=UTF-8" });
    const objectUrl = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = objectUrl;
    link.download = filename;
    document.body.append(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(objectUrl), 0);
  }

  function sourceTypeFor(form) {
    return form instanceof HTMLFormElement && form.dataset.sourceType === "directory"
      ? "directory"
      : "file";
  }

  function fieldValue(form, name) {
    const field = form.querySelector(`[name="${name}"]`);
    return field instanceof HTMLInputElement ? field.value.trim() : "";
  }

  function generatedIdentifier(sourceType) {
    const timestamp = new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 14);
    const random = Math.random().toString(36).slice(2, 8);
    return `publisher-${sourceType}-${timestamp}-${random}`;
  }

  function uploadQueueStatusMessage() {
    if (!state.uploadQueueSortBy) {
      return "Showing upload queue.";
    }
    return `Showing upload queue sorted by ${state.uploadQueueSortBy}${
      state.uploadQueueReversed ? " descending" : ""
    }.`;
  }

  function summaryRow(label, value) {
    const row = document.createElement("p");
    const key = document.createElement("strong");
    key.textContent = `${label}: `;
    row.append(key, document.createTextNode(value == null || value === "" ? "Unavailable" : String(value)));
    return row;
  }

  function text(tagName, className, value) {
    const node = document.createElement(tagName);
    node.className = className;
    node.textContent = value;
    return node;
  }

  function setStatus(message, tone) {
    elements.status.textContent = message || "";
    elements.status.className = statusClassName(tone);
  }

  function statusClassName(tone) {
    switch (tone) {
      case "success":
        return "cr-status cr-status--success";
      case "error":
        return "cr-status cr-status--danger";
      default:
        return "cr-status";
    }
  }

})();
