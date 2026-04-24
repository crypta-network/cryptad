(function () {
  "use strict";

  const appId = "publisher";
  const defaultCompatibilityMode = "COMPAT_CURRENT";
  const state = {
    bootstrap: {},
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
      state.bootstrap = await loadBootstrap();
      initializeForm(elements.fileForm);
      initializeForm(elements.directoryForm);
    } catch (error) {
      setStatus(errorMessage(error), "error");
    }
  }

  function bindControls() {
    elements.fileForm.addEventListener("submit", submitInsert);
    elements.directoryForm.addEventListener("submit", submitInsert);
    elements.uploadQueueButton.addEventListener("click", showUploadQueue);
    elements.result.addEventListener("click", interceptQueueClick);
    elements.result.addEventListener("submit", interceptQueueSubmit);
  }

  async function loadBootstrap() {
    const response = await fetch(`/apps/${appId}/.well-known/cryptad-bootstrap.json`, {
      headers: { Accept: "application/json" },
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(apiError(data, response));
    }
    return data && typeof data === "object" ? data : {};
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
    const path = sourceType === "directory" ? "queue/inserts/directory" : "queue/inserts/file";
    try {
      const result = await postForm(path, buildInsertFormData(form));
      setStatus("Insert queued.", "success");
      renderInsertResult(result);
      form.reset();
      initializeForm(form);
    } catch (error) {
      setStatus(errorMessage(error), "error");
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
      const url = apiUrl("queue");
      url.searchParams.set("page", "uploads");
      if (state.uploadQueueSortBy) {
        url.searchParams.set("sortBy", state.uploadQueueSortBy);
      }
      if (state.uploadQueueReversed) {
        url.searchParams.set("reversed", "true");
      }
      const snapshot = await loadJson(url);
      renderQueue(snapshot.contentHtml);
      setStatus(uploadQueueStatusMessage());
    } catch (error) {
      setStatus(errorMessage(error), "error");
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
    button.className = "button secondary";
    button.type = "button";
    button.textContent = "Show upload queue";
    button.addEventListener("click", showUploadQueue);
    elements.result.replaceChildren(panel, button);
  }

  function renderQueue(contentHtml) {
    const container = document.createElement("div");
    container.className = "legacy-fragment";
    if (typeof contentHtml !== "string" || !contentHtml) {
      container.append(text("p", "empty", "No upload queue content was returned."));
      elements.result.replaceChildren(container);
      return;
    }
    const parsed = new DOMParser().parseFromString(contentHtml, "text/html");
    sanitize(parsed.body);
    container.replaceChildren(...Array.from(parsed.body.childNodes));
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
      const url = apiUrl("queue/keys");
      url.searchParams.set("page", "uploads");
      const data = await loadJson(url);
      const keys = Array.isArray(data.keys)
        ? data.keys.filter((value) => typeof value === "string")
        : [];
      const textBody = keys.length === 0 ? "" : `${keys.join("\n")}\n`;
      downloadTextFile("uploads-keys.txt", textBody);
      setStatus(`Exported ${keys.length} upload queue keys.`, "success");
    } catch (error) {
      setStatus(errorMessage(error), "error");
    }
  }

  function sanitize(root) {
    root
      .querySelectorAll("script, style, template, iframe, frame, frameset, object, embed, link, meta, base")
      .forEach((node) => node.remove());

    root.querySelectorAll("*").forEach((element) => {
      Array.from(element.attributes).forEach((attribute) => {
        const name = attribute.name.toLowerCase();
        if (name.startsWith("on") || name === "style" || name === "srcdoc") {
          element.removeAttribute(attribute.name);
          return;
        }
        if (
          (name === "href" || name === "src" || name === "action" || name === "formaction") &&
          !isSameOrigin(attribute.value)
        ) {
          element.removeAttribute(attribute.name);
        }
      });
    });
  }

  async function postForm(path, formData) {
    const password = typeof state.bootstrap.formPassword === "string" ? state.bootstrap.formPassword : "";
    if (!password) {
      throw new Error("Publisher actions are unavailable.");
    }
    const body = new URLSearchParams();
    for (const [key, value] of formData.entries()) {
      if (typeof value === "string") {
        body.append(key, value);
      }
    }
    body.set("formPassword", password);

    const response = await fetch(apiUrl(path), {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
      },
      body: body.toString(),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(apiError(data, response));
    }
    return data;
  }

  async function loadJson(url) {
    const response = await fetch(url, { headers: { Accept: "application/json" } });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(apiError(data, response));
    }
    return data;
  }

  function apiUrl(path) {
    const root = normalizeLocalRoot(state.bootstrap.platformApiRoot, "/api/v1/");
    return new URL(path, new URL(root, window.location.origin));
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
      return url.origin === window.location.origin && url.pathname === "/uploads/listKeys.txt";
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

  function normalizeLocalRoot(value, fallback) {
    if (typeof value !== "string" || !value.startsWith("/") || value.startsWith("//")) {
      return fallback;
    }
    try {
      const url = new URL(value, window.location.origin);
      if (url.origin !== window.location.origin || url.search || url.hash) {
        return fallback;
      }
      return url.pathname.endsWith("/") ? url.pathname : `${url.pathname}/`;
    } catch (error) {
      return fallback;
    }
  }

  function isSameOrigin(rawValue) {
    const value = typeof rawValue === "string" ? rawValue.trim() : "";
    if (!value || value.startsWith("#")) {
      return true;
    }
    if (value.startsWith("//")) {
      return false;
    }
    try {
      return new URL(value, window.location.href).origin === window.location.origin;
    } catch (error) {
      return false;
    }
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
    elements.status.className = `status ${tone || ""}`.trim();
  }

  function apiError(data, response) {
    if (data && data.error && typeof data.error.message === "string") {
      return data.error.message;
    }
    return `${response.status} ${response.statusText}`;
  }

  function errorMessage(error) {
    return error instanceof Error ? error.message : String(error);
  }
})();
