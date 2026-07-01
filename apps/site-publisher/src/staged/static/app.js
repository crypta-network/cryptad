(function () {
  "use strict";

  const appId = "site-publisher";
  const defaultCompatibilityMode = "COMPAT_CURRENT";
  const maxRecentActions = 5;
  const state = {
    recentActions: [],
    uploadQueueReversed: false,
    uploadQueueSortBy: null,
  };

  const elements = {
    directoryForm: document.getElementById("directory-form"),
    fileForm: document.getElementById("file-form"),
    queuePreview: document.getElementById("queue-preview"),
    recentActions: document.getElementById("recent-actions"),
    refreshQueueButton: document.getElementById("refresh-queue-button"),
    result: document.getElementById("result"),
    secondaryRefreshQueueButton: document.getElementById("secondary-refresh-queue-button"),
    status: document.getElementById("status"),
  };

  document.addEventListener("DOMContentLoaded", start);

  async function start() {
    bindControls();
    try {
      await CryptaPlatform.bootstrap.load({ appId });
      initializeForm(elements.directoryForm);
      initializeForm(elements.fileForm);
      await refreshUploadQueue({ silent: true });
    } catch (error) {
      setStatus(safeErrorMessage(error), "error");
    }
  }

  function bindControls() {
    elements.directoryForm.addEventListener("submit", submitPublish);
    elements.fileForm.addEventListener("submit", submitPublish);
    elements.refreshQueueButton.addEventListener("click", refreshUploadQueue);
    elements.secondaryRefreshQueueButton.addEventListener("click", refreshUploadQueue);
    elements.queuePreview.addEventListener("click", interceptQueueClick);
    elements.queuePreview.addEventListener("submit", interceptQueueSubmit);
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

  async function submitPublish(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const sourceType = sourceTypeFor(form);
    const insert =
      sourceType === "directory"
        ? CryptaPlatform.content.insertDirectory
        : CryptaPlatform.content.insertFile;
    try {
      const result = await insert(buildInsertFormData(form));
      setStatus("Publish request queued.", "success");
      renderInsertResult(result);
      recordRecentAction(result);
      form.reset();
      initializeForm(form);
      await refreshUploadQueue({ silent: true });
    } catch (error) {
      setStatus(safeErrorMessage(error), "error");
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

  async function refreshUploadQueue(options) {
    const refreshOptions = options || {};
    try {
      if (!refreshOptions.silent) {
        setStatus("Loading upload queue...");
      }
      const snapshot = await CryptaPlatform.queue.snapshot({
        page: "uploads",
        sortBy: state.uploadQueueSortBy,
        reversed: state.uploadQueueReversed,
      });
      renderQueue(snapshot.contentHtml);
      if (!refreshOptions.silent) {
        setStatus(uploadQueueStatusMessage());
      }
    } catch (error) {
      if (!refreshOptions.silent) {
        setStatus(safeErrorMessage(error), "error");
      } else {
        renderQueue("");
      }
    }
  }

  function renderInsertResult(data) {
    const panel = document.createElement("div");
    panel.className = "summary";
    panel.append(
      summaryRow("Operation", data.operation),
      summaryRow("Source type", data.sourceType),
      summaryRow("Local path", summarizeLocalPath(data.sourcePath)),
      summaryRow("Insert URI", summarizeInsertUri(data.insertUri)),
      summaryRow("Identifier", data.identifier),
      summaryRow("Outcome", data.outcome),
    );
    elements.result.replaceChildren(panel);
  }

  function recordRecentAction(data) {
    state.recentActions.unshift({
      at: new Date().toLocaleTimeString(),
      identifier: stringValue(data.identifier),
      outcome: stringValue(data.outcome),
      sourceType: stringValue(data.sourceType),
    });
    state.recentActions = state.recentActions.slice(0, maxRecentActions);
    renderRecentActions();
  }

  function renderRecentActions() {
    if (state.recentActions.length === 0) {
      elements.recentActions.replaceChildren(
        text("p", "cr-empty", "Recent actions are kept only in this page's memory."),
      );
      return;
    }
    const list = document.createElement("div");
    list.className = "recent-list";
    for (const action of state.recentActions) {
      const item = document.createElement("div");
      item.className = "recent-item";
      item.append(
        summaryRow("When", action.at),
        summaryRow("Source type", action.sourceType),
        summaryRow("Identifier", action.identifier),
        summaryRow("Outcome", action.outcome),
      );
      list.append(item);
    }
    elements.recentActions.replaceChildren(list);
  }

  function renderQueue(contentHtml) {
    const container = document.createElement("div");
    container.className = "legacy-fragment";
    if (typeof contentHtml !== "string" || !contentHtml) {
      container.append(text("p", "cr-empty", "No upload queue content was returned."));
      elements.queuePreview.replaceChildren(container);
      return;
    }
    container.replaceChildren(CryptaPlatform.dom.sanitizeFragment(contentHtml));
    elements.queuePreview.replaceChildren(container);
  }

  function interceptQueueClick(event) {
    const target = event.target instanceof Element ? event.target : null;
    const anchor = target ? target.closest("a") : null;
    if (!anchor || !elements.queuePreview.contains(anchor)) {
      return;
    }
    if (updateUploadQueueSort(anchor.getAttribute("href") || "")) {
      event.preventDefault();
      return;
    }
    event.preventDefault();
    setStatus("Open Queue Manager for detailed queue actions.", "error");
  }

  function interceptQueueSubmit(event) {
    const form = event.target;
    if (!(form instanceof HTMLFormElement)) {
      return;
    }
    event.preventDefault();
    setStatus("Open Queue Manager for detailed queue actions.", "error");
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
    refreshUploadQueue();
    return true;
  }

  function sourceTypeFor(form) {
    return form instanceof HTMLFormElement && form.dataset.sourceType === "file"
      ? "file"
      : "directory";
  }

  function fieldValue(form, name) {
    const field = form.querySelector(`[name="${name}"]`);
    return field instanceof HTMLInputElement ? field.value.trim() : "";
  }

  function generatedIdentifier(sourceType) {
    const timestamp = new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 14);
    const random = Math.random().toString(36).slice(2, 8);
    return `site-publisher-${sourceType}-${timestamp}-${random}`;
  }

  function uploadQueueStatusMessage() {
    if (!state.uploadQueueSortBy) {
      return "Showing upload queue.";
    }
    return `Showing upload queue sorted by ${state.uploadQueueSortBy}${
      state.uploadQueueReversed ? " descending" : ""
    }.`;
  }

  function summarizeLocalPath(value) {
    const path = stringValue(value);
    if (!path) {
      return "Operator-provided path accepted.";
    }
    const parts = path.split(/[\\/]/).filter(Boolean);
    const leaf = parts.length > 0 ? parts[parts.length - 1] : "";
    return leaf ? `Operator-provided path ending in "${leaf}" accepted.` : "Operator-provided path accepted.";
  }

  function summarizeInsertUri(value) {
    const uri = stringValue(value);
    const match = uri.match(/^\s*([A-Za-z]+)@/);
    if (match) {
      return `${match[1].toUpperCase()} insert URI submitted.`;
    }
    return "Operator-provided insert URI submitted.";
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

  function stringValue(value) {
    return value == null ? "" : String(value);
  }

  function safeErrorMessage(error) {
    const fallback = "Site publish request failed. Retry validation or use Operator RC Recovery.";
    let message = "";
    try {
      message =
        CryptaPlatform.api && typeof CryptaPlatform.api.errorMessage === "function"
          ? CryptaPlatform.api.errorMessage(error)
          : error && error.message;
    } catch (_) {
      message = "";
    }
    message = String(message || "").replace(/\s+/g, " ").trim();
    if (!message || sensitiveDiagnosticPattern().test(message)) {
      return fallback;
    }
    return message.slice(0, 240);
  }

  function sensitiveDiagnosticPattern() {
    return /(crypta:(?:ssk|usk)@|(?:ssk|usk)@|authorization|bearer|token|private key|identity material|browser session|form password|raw (?:content|message|app data)|[A-Za-z]:\\|\/(?:home|Users|work|tmp|var)\/)/i;
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
