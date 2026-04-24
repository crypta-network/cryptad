(function () {
  "use strict";

  const appId = "queue-manager";
  const state = {
    bootstrap: {},
    page: "downloads",
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
      state.bootstrap = await loadBootstrap();
      await loadQueue();
    } catch (error) {
      setStatus(errorMessage(error), "error");
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

  async function selectPage(page) {
    state.page = page;
    updateTabs();
    await loadQueue();
  }

  async function loadQueue() {
    renderText("Loading queue snapshot...");
    setStatus("");
    try {
      const url = apiUrl("queue");
      url.searchParams.set("page", state.page);
      const snapshot = await loadJson(url);
      renderQueue(snapshot.contentHtml);
      setStatus(`Showing ${state.page}.`);
    } catch (error) {
      setStatus(errorMessage(error), "error");
      renderText("Queue snapshot unavailable.");
    }
  }

  function renderQueue(contentHtml) {
    elements.content.replaceChildren();
    const fragment = document.createElement("div");
    fragment.className = "legacy-fragment";
    if (typeof contentHtml !== "string" || contentHtml.length === 0) {
      fragment.append(text("p", "empty", "No queue content was returned."));
      elements.content.append(fragment);
      return;
    }

    const parsed = new DOMParser().parseFromString(contentHtml, "text/html");
    sanitize(parsed.body);
    fragment.replaceChildren(...Array.from(parsed.body.childNodes));
    elements.content.append(fragment);
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

  function interceptQueueClick(event) {
    const target = event.target instanceof Element ? event.target : null;
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

  function interceptQueueSubmit(event) {
    const form = event.target;
    if (!(form instanceof HTMLFormElement)) {
      return;
    }
    const submitter = event.submitter || form.querySelector("button, input[type='submit']");
    const path = queueMutationPath(submitter && submitter.name);
    if (!path) {
      return;
    }
    event.preventDefault();
    submitQueueMutation(new FormData(form, submitter), submitter, path);
  }

  async function submitQueueMutation(source, submitter, path) {
    const body = filterQueueFormData(source, submitter, path);
    try {
      const result = await postForm(path, body);
      const operation = result.operation || submitter.name || "queue action";
      setStatus(`Completed ${String(operation).replaceAll("_", " ")}.`, "success");
      await loadQueue();
    } catch (error) {
      setStatus(errorMessage(error), "error");
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

  async function submitDirectDownload(event) {
    event.preventDefault();
    try {
      await postForm("queue/downloads", new FormData(elements.directDownloadForm));
      elements.directDownloadForm.reset();
      elements.directDownloadForm.querySelector('input[name="filterData"]').checked = true;
      setStatus("Direct download queued.", "success");
      state.page = "downloads";
      updateTabs();
      await loadQueue();
    } catch (error) {
      setStatus(errorMessage(error), "error");
    }
  }

  async function postForm(path, formData) {
    const password = typeof state.bootstrap.formPassword === "string" ? state.bootstrap.formPassword : "";
    if (!password) {
      throw new Error("Mutating queue actions are unavailable.");
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

  function updateTabs() {
    const downloads = state.page === "downloads";
    elements.downloadsTab.classList.toggle("active", downloads);
    elements.uploadsTab.classList.toggle("active", !downloads);
    elements.downloadsTab.setAttribute("aria-selected", downloads ? "true" : "false");
    elements.uploadsTab.setAttribute("aria-selected", downloads ? "false" : "true");
    elements.downloadPanel.hidden = !downloads;
  }

  function renderText(value) {
    elements.content.replaceChildren(text("p", "empty", value));
  }

  function setStatus(message, tone) {
    elements.status.textContent = message || "";
    elements.status.className = `status ${tone || ""}`.trim();
  }

  function text(tagName, className, value) {
    const node = document.createElement(tagName);
    node.className = className;
    node.textContent = value;
    return node;
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
