(function () {
  "use strict";

  const appId = "queue-manager";
  const state = {
    page: "downloads",
    reversed: false,
    sortBy: null,
  };

  const elements = {
    content: document.getElementById("queue-content"),
    status: document.getElementById("status"),
    refresh: document.getElementById("refresh-button"),
    downloadsTab: document.getElementById("downloads-tab"),
    uploadsTab: document.getElementById("uploads-tab"),
    downloadPanel: document.getElementById("download-panel"),
    directDownloadForm: document.getElementById("direct-download-form"),
  };

  document.addEventListener("DOMContentLoaded", start);

  async function start() {
    bindControls();
    try {
      await CryptaPlatform.bootstrap.load({ appId });
      await loadQueue();
    } catch (error) {
      setStatus(CryptaPlatform.api.errorMessage(error), "error");
      renderText("Queue Manager is not ready.");
    }
  }

  function bindControls() {
    elements.refresh.addEventListener("click", () => loadQueue());
    elements.downloadsTab.addEventListener("click", () => selectPage("downloads"));
    elements.uploadsTab.addEventListener("click", () => selectPage("uploads"));
    elements.directDownloadForm.addEventListener("submit", submitDirectDownload);
    elements.content.addEventListener("submit", interceptQueueSubmit);
    elements.content.addEventListener("click", interceptQueueClick);
  }

  async function selectPage(page) {
    if (state.page !== page) {
      state.sortBy = null;
      state.reversed = false;
    }
    state.page = page;
    updateTabs();
    await loadQueue();
  }

  async function loadQueue() {
    renderText("Loading queue snapshot...");
    setStatus("");
    try {
      const snapshot = await CryptaPlatform.queue.snapshot({
        page: state.page,
        sortBy: state.sortBy,
        reversed: state.reversed,
      });
      renderQueue(snapshot.contentHtml);
      setStatus(queueStatusMessage());
    } catch (error) {
      setStatus(CryptaPlatform.api.errorMessage(error), "error");
      renderText("Queue snapshot unavailable.");
    }
  }

  function renderQueue(contentHtml) {
    elements.content.replaceChildren();
    const fragment = document.createElement("div");
    fragment.className = "legacy-fragment";
    if (typeof contentHtml !== "string" || contentHtml.length === 0) {
      fragment.append(text("p", "cr-empty", "No queue content was returned."));
      elements.content.append(fragment);
      return;
    }

    fragment.replaceChildren(CryptaPlatform.dom.sanitizeFragment(contentHtml));
    elements.content.append(fragment);
  }

  function interceptQueueClick(event) {
    const target = event.target instanceof Element ? event.target : null;
    const anchor = target ? target.closest("a") : null;
    if (anchor && elements.content.contains(anchor) && interceptQueueAnchor(event, anchor)) {
      return;
    }
    const button = target ? target.closest("button, input[type='submit']") : null;
    if (!button || !elements.content.contains(button)) {
      return;
    }
    const form = button.form;
    if (form && elements.content.contains(form)) {
      return;
    }
    const path = queueMutationPath(button.name);
    if (!path) {
      return;
    }
    event.preventDefault();
    submitQueueMutation(new FormData(), button, path);
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
    if (isQueueKeyListLink(href)) {
      event.preventDefault();
      exportQueueKeys();
      return true;
    }
    if (updateQueueSort(href)) {
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
    const path = queueMutationPath(submitter && submitter.name);
    event.preventDefault();
    if (!path) {
      setStatus(unsupportedQueueAction(submitter && submitter.name), "error");
      return;
    }
    submitQueueMutation(new FormData(form, submitter), submitter, path);
  }

  async function submitQueueMutation(source, submitter, path) {
    const body = filterQueueFormData(source, submitter, path);
    try {
      const result = await CryptaPlatform.queue.mutate(path, body);
      const operation = result.operation || submitter.name || "queue action";
      setStatus(`Completed ${String(operation).replaceAll("_", " ")}.`, "success");
      await loadQueue();
    } catch (error) {
      setStatus(CryptaPlatform.api.errorMessage(error), "error");
    }
  }

  function filterQueueFormData(source, submitter, path) {
    const body = new FormData();
    for (const [key, value] of source.entries()) {
      if (typeof value !== "string") {
        continue;
      }
      if (key === "identifier" || key.indexOf("identifier-") === 0) {
        body.append(key, value);
      }
    }
    if (path === "queue/requests/restart" && source.has("disableFilterData")) {
      body.append("disableFilterData", "disableFilterData");
    }
    if (path === "queue/requests/priority") {
      const priority = priorityValue(source, submitter && submitter.name);
      if (priority) {
        body.set("priority", priority);
      }
    }
    return body;
  }

  function priorityValue(source, submitterName) {
    if (submitterName === "change_priority_top") {
      return source.get("priority_top");
    }
    if (submitterName === "change_priority_bottom") {
      return source.get("priority_bottom");
    }
    return source.get("priority");
  }

  function queueMutationPath(submitterName) {
    switch (submitterName) {
      case "remove_request":
        return "queue/requests/remove";
      case "restart_request":
        return "queue/requests/restart";
      case "remove_finished_uploads_request":
        return "queue/cleanup/uploads";
      case "remove_finished_downloads_request":
        return "queue/cleanup/downloads";
      default:
        if (submitterName && submitterName.indexOf("change_priority") === 0) {
          return "queue/requests/priority";
        }
        return null;
    }
  }

  function unsupportedQueueAction(submitterName) {
    const action = typeof submitterName === "string" ? submitterName.replaceAll("_", " ") : "";
    if (!action) {
      return "Queue action is not supported by Platform API yet.";
    }
    return `Queue action "${action}" is not supported by Platform API yet.`;
  }

  async function submitDirectDownload(event) {
    event.preventDefault();
    try {
      await CryptaPlatform.queue.directDownload(new FormData(elements.directDownloadForm));
      elements.directDownloadForm.reset();
      elements.directDownloadForm.querySelector('input[name="filterData"]').checked = true;
      setStatus("Direct download queued.", "success");
      state.page = "downloads";
      updateTabs();
      await loadQueue();
    } catch (error) {
      setStatus(CryptaPlatform.api.errorMessage(error), "error");
    }
  }

  async function exportQueueKeys() {
    setStatus(`Preparing ${state.page} key list...`);
    try {
      const url = CryptaPlatform.api.url("queue/keys");
      url.searchParams.set("page", state.page);
      const data = await CryptaPlatform.api.get(url);
      const keys = Array.isArray(data.keys)
        ? data.keys.filter((value) => typeof value === "string")
        : [];
      const textBody = keys.length === 0 ? "" : `${keys.join("\n")}\n`;
      downloadTextFile(`${state.page}-keys.txt`, textBody);
      setStatus(`Exported ${keys.length} ${state.page} queue keys.`, "success");
    } catch (error) {
      setStatus(CryptaPlatform.api.errorMessage(error), "error");
    }
  }

  function updateQueueSort(rawHref) {
    if (typeof rawHref !== "string" || !rawHref.startsWith("?")) {
      return false;
    }
    const params = new URLSearchParams(rawHref.slice(1));
    if (!params.has("sortBy")) {
      return false;
    }
    state.sortBy = params.get("sortBy");
    state.reversed = params.get("reversed") === "true" || params.has("reversed");
    loadQueue();
    return true;
  }

  function isQueueKeyListLink(rawHref) {
    const href = typeof rawHref === "string" ? rawHref.trim() : "";
    if (href === "listKeys.txt") {
      return true;
    }
    if (!href || href.startsWith("?") || href.startsWith("#") || href.startsWith("//")) {
      return false;
    }
    try {
      const url = new URL(href, window.location.href);
      return (
        CryptaPlatform.dom.sameOrigin(url.href) &&
        (url.pathname === "/downloads/listKeys.txt" || url.pathname === "/uploads/listKeys.txt")
      );
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

  function updateTabs() {
    const downloads = state.page === "downloads";
    elements.downloadsTab.classList.toggle("active", downloads);
    elements.uploadsTab.classList.toggle("active", !downloads);
    elements.downloadsTab.setAttribute("aria-selected", downloads ? "true" : "false");
    elements.uploadsTab.setAttribute("aria-selected", downloads ? "false" : "true");
    elements.downloadPanel.hidden = !downloads;
  }

  function queueStatusMessage() {
    if (!state.sortBy) {
      return `Showing ${state.page}.`;
    }
    return `Showing ${state.page} sorted by ${state.sortBy}${state.reversed ? " descending" : ""}.`;
  }

  function renderText(value) {
    elements.content.replaceChildren(text("p", "cr-empty", value));
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

  function text(tagName, className, value) {
    const node = document.createElement(tagName);
    node.className = className;
    node.textContent = value;
    return node;
  }

})();
