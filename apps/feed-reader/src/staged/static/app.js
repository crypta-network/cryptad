(function () {
  "use strict";

  const appId = "feed-reader";
  const maxSources = 12;
  const maxEntriesPerSnapshot = 20;
  const maxRememberedSnapshots = 12;
  const maxPublishResults = 5;
  const maxFollowRefreshesPerOpen = 24;
  const followRefreshMillis = 5 * 60 * 1000;

  const state = {
    sources: [],
    selectedSourceId: "",
    fetchedSnapshots: [],
    publishResults: [],
    followTimerId: 0,
    followRefreshCount: 0,
    uploadQueueSortBy: null,
    uploadQueueReversed: false,
  };

  const elements = {
    followStatus: document.getElementById("follow-status"),
    followToggleButton: document.getElementById("follow-toggle-button"),
    publisherForm: document.getElementById("publisher-form"),
    publishResult: document.getElementById("publish-result"),
    queuePreview: document.getElementById("queue-preview"),
    readerContent: document.getElementById("reader-content"),
    refreshQueueButton: document.getElementById("refresh-queue-button"),
    refreshSelectedButton: document.getElementById("refresh-selected-button"),
    secondaryRefreshQueueButton: document.getElementById("secondary-refresh-queue-button"),
    sourceForm: document.getElementById("source-form"),
    sourceList: document.getElementById("source-list"),
    status: document.getElementById("status"),
  };

  document.addEventListener("DOMContentLoaded", start);
  window.addEventListener("pagehide", stopFollowTimer);
  document.addEventListener("visibilitychange", stopFollowTimerWhenHidden);

  async function start() {
    bindControls();
    try {
      await CryptaPlatform.bootstrap.load({ appId });
      renderSources();
      renderReader();
      await refreshUploadQueue({ silent: true });
    } catch (error) {
      setStatus(CryptaPlatform.api.errorMessage(error), "error");
    }
  }

  function bindControls() {
    elements.sourceForm.addEventListener("submit", addSource);
    elements.publisherForm.addEventListener("submit", publishSnapshot);
    elements.followToggleButton.addEventListener("click", toggleFollowTimer);
    elements.refreshSelectedButton.addEventListener("click", refreshSelectedSource);
    elements.refreshQueueButton.addEventListener("click", refreshUploadQueue);
    elements.secondaryRefreshQueueButton.addEventListener("click", refreshUploadQueue);
  }

  function addSource(event) {
    event.preventDefault();
    if (state.sources.length >= maxSources) {
      setStatus("Source limit reached for this page.", "error");
      return;
    }
    const source = {
      label: fieldValue(elements.sourceForm, "label"),
      uri: fieldValue(elements.sourceForm, "uri"),
      followUsk: checkboxValue(elements.sourceForm, "followUsk"),
    };
    addSourceToState(source);
    elements.sourceForm.reset();
    renderSources();
    setStatus("Feed source added.");
  }

  function addSourceToState(source) {
    const id = generatedId("source");
    state.sources.unshift({
      id,
      label: stringValue(source.label) || "Untitled feed",
      uri: stringValue(source.uri),
      followUsk: !!source.followUsk,
      lastFetchedAt: "",
      lastStatus: "Not fetched",
    });
    state.selectedSourceId = id;
  }

  async function refreshSelectedSource() {
    const source = selectedSource();
    if (!source) {
      setStatus("Select or add a feed source first.", "error");
      return;
    }
    await refreshSource(source, { follow: source.followUsk });
  }

  async function refreshSource(source, options) {
    try {
      setStatus("Fetching feed snapshot...");
      const snapshot = await fetchSourceSnapshot(source, options || {});
      source.lastFetchedAt = new Date().toLocaleTimeString();
      source.lastStatus = "Fetched";
      rememberSnapshot(normalizeSnapshot(source, snapshot));
      renderSources();
      renderReader();
      setStatus("Feed snapshot fetched.", "success");
    } catch (error) {
      source.lastStatus = CryptaPlatform.api.errorMessage(error);
      renderSources();
      setStatus(source.lastStatus, "error");
    }
  }

  async function fetchSourceSnapshot(source, options) {
    const request = {
      uri: source.uri,
      maxBytes: 262144,
      timeoutMillis: 30000,
      purpose: options.follow && isUskUri(source.uri) ? "feed-source" : "feed-preview",
    };
    if (
      CryptaPlatform.content &&
      typeof CryptaPlatform.content.fetchText === "function"
    ) {
      const response = await CryptaPlatform.content.fetchText(request);
      return snapshotFromTextResponse(source, response);
    }
    if (
      CryptaPlatform.feed &&
      typeof CryptaPlatform.feed.fetchSnapshot === "function"
    ) {
      return CryptaPlatform.feed.fetchSnapshot(request);
    }
    throw new Error("Feed fetch helper is unavailable.");
  }

  async function publishSnapshot(event) {
    event.preventDefault();
    try {
      const entry = buildDraftEntry(elements.publisherForm);
      const snapshot = buildPublishedSnapshot(elements.publisherForm, entry);
      const result = await CryptaPlatform.feed.publishSnapshot({
        insertUri: fieldValue(elements.publisherForm, "insertUri"),
        identifier: fieldValue(elements.publisherForm, "identifier") || generatedId("feed-publish"),
        snapshot,
        contentType: "application/vnd.crypta.feed+json",
        targetFilename: "feed.json",
      });
      rememberPublishResult(result);
      elements.publisherForm.reset();
      renderPublishResults();
      await refreshUploadQueue({ silent: true });
      setStatus("Feed snapshot publish queued.", "success");
    } catch (error) {
      setStatus(CryptaPlatform.api.errorMessage(error), "error");
    }
  }

  function toggleFollowTimer() {
    if (state.followTimerId) {
      stopFollowTimer();
      return;
    }
    state.followRefreshCount = 0;
    state.followTimerId = window.setInterval(refreshFollowedUskSources, followRefreshMillis);
    elements.followToggleButton.textContent = "Stop USK follow";
    setFollowStatus("USK follow refresh is active for this tab.");
    refreshFollowedUskSources();
  }

  async function refreshFollowedUskSources() {
    if (state.followRefreshCount >= maxFollowRefreshesPerOpen) {
      stopFollowTimer();
      setFollowStatus("USK follow refresh stopped after the bounded refresh count.");
      return;
    }
    const sources = state.sources.filter((source) => source.followUsk && isUskUri(source.uri));
    if (sources.length === 0) {
      setFollowStatus("No USK sources are marked for follow refresh.");
      return;
    }
    state.followRefreshCount += 1;
    for (const source of sources) {
      await refreshSource(source, { follow: true });
    }
    setFollowStatus(`USK follow refresh ${state.followRefreshCount} completed.`);
  }

  function stopFollowTimerWhenHidden() {
    if (document.visibilityState === "hidden") {
      stopFollowTimer();
    }
  }

  function stopFollowTimer() {
    if (!state.followTimerId) {
      return;
    }
    window.clearInterval(state.followTimerId);
    state.followTimerId = 0;
    elements.followToggleButton.textContent = "Start USK follow";
    setFollowStatus("USK follow refresh is stopped.");
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
      renderQueue(snapshot);
      if (!refreshOptions.silent) {
        setStatus("Upload queue preview refreshed.");
      }
    } catch (error) {
      if (!refreshOptions.silent) {
        setStatus(CryptaPlatform.api.errorMessage(error), "error");
      }
      renderQueue(null);
    }
  }

  function renderSources() {
    if (state.sources.length === 0) {
      elements.sourceList.replaceChildren(text("p", "cr-empty", "Add a feed source to fetch entries."));
      return;
    }
    const list = document.createElement("div");
    list.className = "source-list";
    state.sources.forEach((source) => {
      const item = document.createElement("div");
      item.className = "source-item";
      const title = text("p", "entry-title", source.label);
      const uri = text("p", "source-uri", source.uri);
      const status = text(
        "p",
        "entry-meta",
        source.lastFetchedAt ? `${source.lastStatus} at ${source.lastFetchedAt}` : source.lastStatus,
      );
      const actions = document.createElement("div");
      actions.className = "source-item__actions";
      actions.append(
        button("Select", "cr-button cr-button--secondary", () => selectSource(source.id)),
        button("Fetch", "cr-button cr-button--primary", () => refreshSource(source, { follow: false })),
      );
      item.append(title, uri, status, actions);
      list.append(item);
    });
    elements.sourceList.replaceChildren(list);
  }

  function renderReader() {
    const snapshot = selectedSnapshot();
    if (!snapshot) {
      elements.readerContent.replaceChildren(
        text("p", "cr-empty", "Fetched feed content appears here as plain text."),
      );
      return;
    }
    const panel = document.createElement("div");
    panel.className = "reader-content";
    panel.append(
      summaryRow("Source", snapshot.sourceLabel),
      summaryRow("Fetched", snapshot.fetchedAt),
      summaryRow("Feed", snapshot.title),
      summaryRow("Updated", snapshot.updatedAt),
      summaryRow("URI", snapshot.sourceUri),
      summaryRow("Resolved", snapshot.resolvedUri),
      summaryRow("Bytes", snapshot.bytesLength),
    );
    if (snapshot.items.length === 0) {
      panel.append(text("p", "cr-empty", "No entries were returned for this snapshot."));
    }
    snapshot.items.forEach((entry) => {
      const item = document.createElement("article");
      item.className = "entry-item";
      item.append(
        text("h3", "entry-title", entry.title),
        text("p", "entry-meta", entry.publishedAt),
        text("p", "entry-body", entry.summary),
        text("p", "source-uri", entry.uri),
        text("p", "entry-meta", entry.tags.join(", ")),
      );
      panel.append(item);
    });
    elements.readerContent.replaceChildren(panel);
  }

  function renderPublishResults() {
    if (state.publishResults.length === 0) {
      elements.publishResult.replaceChildren(
        text("p", "cr-empty", "Publish results stay only in this page's memory."),
      );
      return;
    }
    const list = document.createElement("div");
    list.className = "publish-summary";
    state.publishResults.forEach((result) => {
      const item = document.createElement("div");
      item.className = "publish-item";
      item.append(
        summaryRow("When", result.at),
        summaryRow("Identifier", result.identifier),
        summaryRow("Outcome", result.outcome),
      );
      list.append(item);
    });
    elements.publishResult.replaceChildren(list);
  }

  function renderQueue(snapshot) {
    if (!snapshot || typeof snapshot !== "object") {
      elements.queuePreview.replaceChildren(text("p", "cr-empty", "No upload queue content was returned."));
      return;
    }
    const panel = document.createElement("div");
    panel.className = "queue-content";
    panel.append(
      summaryRow("Queue page", stringValue(snapshot.page) || "uploads"),
      summaryRow("Title", stringValue(snapshot.pageTitle) || "Upload queue"),
    );
    const rows = queueRowsFromSnapshot(snapshot).slice(0, 10);
    if (rows.length === 0) {
      panel.append(text("p", "cr-empty", "No visible upload queue entries were returned."));
    }
    rows.forEach((item) => {
      const row = document.createElement("div");
      row.className = "queue-item";
      row.append(text("p", "entry-title", item.label), text("p", "entry-body", item.detail));
      panel.append(row);
    });
    elements.queuePreview.replaceChildren(panel);
  }

  function queueRowsFromSnapshot(snapshot) {
    if (Array.isArray(snapshot.items)) {
      return snapshot.items.map(queueRowFromItem).filter(Boolean);
    }
    const rows = queueRowsFromHtml(snapshot.contentHtml);
    if (rows.length > 0) {
      return rows;
    }
    const summary = compactQueueText(snapshot.summary);
    return summary ? [{ label: "Summary", detail: summary }] : [];
  }

  function queueRowFromItem(item) {
    if (!item || typeof item !== "object") {
      return null;
    }
    const label = stringValue(item.identifier || item.name || item.id) || "Queue item";
    const detail = [
      item.status || item.outcome,
      item.uri || item.insertUri || item.targetUri,
      item.progress || item.priority,
    ]
      .map(compactQueueText)
      .filter(Boolean)
      .join(" | ");
    return { label, detail: detail || "Queued" };
  }

  function queueRowsFromHtml(contentHtml) {
    const html = typeof contentHtml === "string" ? contentHtml : "";
    if (!html.trim()) {
      return [];
    }
    const documentValue = new DOMParser().parseFromString(html, "text/html");
    documentValue.querySelectorAll("script, style, template, noscript").forEach((node) => node.remove());
    const tableRows = Array.from(documentValue.querySelectorAll("tr"))
      .map(queueRowFromTableRow)
      .filter(Boolean);
    if (tableRows.length > 0) {
      return tableRows;
    }
    const listRows = queueRowsFromNodes(documentValue.querySelectorAll("li"), "Queue item");
    if (listRows.length > 0) {
      return listRows;
    }
    const paragraphRows = queueRowsFromNodes(documentValue.querySelectorAll("p"), "Queue status");
    if (paragraphRows.length > 0) {
      return paragraphRows;
    }
    const bodyText = compactQueueText(documentValue.body && documentValue.body.textContent);
    return bodyText ? [{ label: "Queue snapshot", detail: bodyText }] : [];
  }

  function queueRowFromTableRow(row) {
    const cells = Array.from(row.querySelectorAll("td")).map((cell) => compactQueueText(cell.textContent));
    const visibleCells = cells.filter(Boolean);
    if (visibleCells.length === 0) {
      return null;
    }
    return {
      label: visibleCells[0] || "Queue item",
      detail: visibleCells.slice(1).join(" | ") || visibleCells[0],
    };
  }

  function queueRowsFromNodes(nodes, label) {
    return Array.from(nodes)
      .map((node) => compactQueueText(node.textContent))
      .filter(Boolean)
      .map((detail) => ({ label, detail }));
  }

  function normalizeSnapshot(source, snapshot) {
    const response = snapshot && snapshot.response ? snapshot.response : {};
    const feedSnapshot = snapshot && snapshot.snapshot ? snapshot.snapshot : snapshot;
    const feedSource =
      feedSnapshot && feedSnapshot.source && typeof feedSnapshot.source === "object"
        ? feedSnapshot.source
        : {};
    const items = itemsFromSnapshot(feedSnapshot).slice(0, maxEntriesPerSnapshot);
    return {
      sourceId: source.id,
      sourceLabel: source.label,
      sourceUri: source.uri,
      resolvedUri: stringValue(feedSource.resolvedUri || response.resolvedUri),
      bytesLength: stringValue(response.bytesLength),
      title: stringValue(feedSnapshot && feedSnapshot.title) || source.label,
      updatedAt: stringValue(feedSnapshot && feedSnapshot.updatedAt),
      fetchedAt: new Date().toLocaleTimeString(),
      items,
    };
  }

  function itemsFromSnapshot(snapshot) {
    if (snapshot && Array.isArray(snapshot.items)) {
      return snapshot.items.map(normalizeEntry);
    }
    if (snapshot && Array.isArray(snapshot.entries)) {
      return snapshot.entries.map(normalizeEntry);
    }
    if (snapshot && typeof snapshot.contentText === "string") {
      return itemsFromText(snapshot.contentText);
    }
    if (snapshot && typeof snapshot.text === "string") {
      return itemsFromText(snapshot.text);
    }
    if (snapshot && typeof snapshot.content === "string") {
      return itemsFromText(snapshot.content);
    }
    if (typeof snapshot === "string") {
      return itemsFromText(snapshot);
    }
    return [];
  }

  function itemsFromText(textValue) {
    const sourceText = stringValue(textValue);
    if (!sourceText) {
      return [];
    }
    const parsed = parseXmlFeed(sourceText);
    if (parsed.length > 0) {
      return parsed;
    }
    return [
      {
        title: "Fetched text",
        publishedAt: new Date().toISOString(),
        summary: sourceText,
        uri: "",
        tags: [],
      },
    ];
  }

  function parseXmlFeed(textValue) {
    const parser = new DOMParser();
    const documentValue = parser.parseFromString(textValue, "application/xml");
    if (documentValue.querySelector("parsererror")) {
      return [];
    }
    const items = Array.from(documentValue.querySelectorAll("item, entry"));
    return items.slice(0, maxEntriesPerSnapshot).map((item) => ({
      title: childText(item, "title") || "Untitled entry",
      publishedAt:
        childText(item, "updated") || childText(item, "published") || childText(item, "pubDate"),
      summary: childText(item, "summary") || childText(item, "description") || childText(item, "content"),
      uri: entryLink(item),
      tags: [],
    }));
  }

  function snapshotFromTextResponse(source, response) {
    const textValue =
      typeof response === "string"
        ? response
        : stringValue(
            response && (response.contentText || response.text || response.content || response.body),
          );
    const parsedSnapshot = parseCanonicalSnapshot(textValue);
    if (parsedSnapshot) {
      return { response, snapshot: parsedSnapshot };
    }
    return {
      response,
      snapshot: {
        type: "crypta.feed.snapshot.v1",
        title: source.label,
        updatedAt: new Date().toISOString(),
        source: {
          uri: source.uri,
          resolvedUri: stringValue(response && response.resolvedUri),
        },
        author: {},
        items: itemsFromText(textValue),
      },
    };
  }

  function parseCanonicalSnapshot(textValue) {
    const sourceText = stringValue(textValue);
    if (
      !sourceText ||
      !CryptaPlatform.feed ||
      typeof CryptaPlatform.feed.parseSnapshot !== "function"
    ) {
      return null;
    }
    try {
      return CryptaPlatform.feed.parseSnapshot(sourceText);
    } catch (error) {
      return null;
    }
  }

  function buildDraftEntry(form) {
    return {
      id: generatedId("entry"),
      title: fieldValue(form, "entryTitle"),
      summary: fieldValue(form, "entryBody"),
      uri: fieldValue(form, "entryUri"),
      publishedAt: new Date().toISOString(),
      tags: tagsFromField(fieldValue(form, "entryTags")),
    };
  }

  function buildPublishedSnapshot(form, entry) {
    const source = selectedSource();
    const snapshot = selectedSnapshot();
    return {
      type: "crypta.feed.snapshot.v1",
      title: fieldValue(form, "feedTitle") || (source ? source.label : "Feed snapshot"),
      updatedAt: new Date().toISOString(),
      source: {
        uri: source ? source.uri : "",
        resolvedUri: snapshot ? snapshot.resolvedUri : "",
      },
      author: {
        name: fieldValue(form, "authorName"),
        profileUri: fieldValue(form, "authorProfileUri"),
      },
      items: [entry].concat(snapshot ? snapshot.items : []).slice(0, maxEntriesPerSnapshot),
    };
  }

  function rememberSnapshot(snapshot) {
    state.fetchedSnapshots.unshift(snapshot);
    state.fetchedSnapshots = state.fetchedSnapshots.slice(0, maxRememberedSnapshots);
    state.selectedSourceId = snapshot.sourceId;
  }

  function rememberPublishResult(result) {
    state.publishResults.unshift({
      at: new Date().toLocaleTimeString(),
      identifier: stringValue(result && (result.identifier || result.requestIdentifier || result.requestId)),
      outcome: stringValue(result && (result.outcome || result.status)) || "Queued",
    });
    state.publishResults = state.publishResults.slice(0, maxPublishResults);
  }

  function selectSource(sourceId) {
    state.selectedSourceId = sourceId;
    renderSources();
    renderReader();
  }

  function selectedSource() {
    return state.sources.find((source) => source.id === state.selectedSourceId) || state.sources[0] || null;
  }

  function selectedSnapshot() {
    if (state.selectedSourceId) {
      return (
        state.fetchedSnapshots.find((snapshot) => snapshot.sourceId === state.selectedSourceId) ||
        null
      );
    }
    const source = state.sources[0] || null;
    if (source) {
      return state.fetchedSnapshots.find((snapshot) => snapshot.sourceId === source.id) || null;
    }
    return state.fetchedSnapshots[0] || null;
  }

  function normalizeEntry(entry) {
    return {
      title: stringValue(entry && entry.title) || "Untitled entry",
      publishedAt: stringValue(entry && (entry.publishedAt || entry.date || entry.updated || entry.published)),
      summary: stringValue(entry && (entry.summary || entry.body || entry.content || entry.text)),
      uri: stringValue(entry && entry.uri),
      tags: Array.isArray(entry && entry.tags)
        ? entry.tags.map(stringValue).filter(Boolean).slice(0, 12)
        : [],
    };
  }

  function childText(element, selector) {
    const child = element.querySelector(selector);
    return child ? stringValue(child.textContent) : "";
  }

  function entryLink(element) {
    const link = element.querySelector("link[rel=\"alternate\"]") || element.querySelector("link");
    if (!link) {
      return "";
    }
    return stringValue(link.getAttribute("href")) || stringValue(link.textContent);
  }

  function fieldValue(form, name) {
    const field = form.elements.namedItem(name);
    return field && "value" in field ? stringValue(field.value) : "";
  }

  function checkboxValue(form, name) {
    const field = form.elements.namedItem(name);
    return field instanceof HTMLInputElement && field.checked;
  }

  function isUskUri(value) {
    const uri = stringValue(value);
    const withoutScheme = uri.toLowerCase().startsWith("crypta:") ? uri.slice(7) : uri;
    return withoutScheme.toUpperCase().startsWith("USK@");
  }

  function tagsFromField(value) {
    return stringValue(value)
      .split(",")
      .map(stringValue)
      .filter(Boolean)
      .slice(0, 12);
  }

  function stringValue(value) {
    return typeof value === "string" ? value.trim() : value == null ? "" : String(value).trim();
  }

  function compactQueueText(value) {
    const textValue = stringValue(value).replace(/\s+/g, " ");
    return textValue.length > 260 ? `${textValue.slice(0, 257)}...` : textValue;
  }

  function generatedId(prefix) {
    const timestamp = new Date().toISOString().replace(/[-:.TZ]/g, "");
    const random = Math.random().toString(36).slice(2, 8);
    return `${prefix}-${timestamp}-${random}`;
  }

  function summaryRow(label, value) {
    const row = document.createElement("p");
    row.className = "summary-row";
    const strong = document.createElement("strong");
    strong.textContent = `${label}: `;
    row.append(strong, document.createTextNode(stringValue(value) || "Unavailable"));
    return row;
  }

  function text(tagName, className, value) {
    const element = document.createElement(tagName);
    element.className = className;
    element.textContent = stringValue(value);
    return element;
  }

  function button(label, className, action) {
    const element = document.createElement("button");
    element.className = className;
    element.type = "button";
    element.textContent = label;
    element.addEventListener("click", action);
    return element;
  }

  function setStatus(message, kind) {
    elements.status.textContent = stringValue(message);
    elements.status.className = `cr-status ${statusClass(kind)}`;
  }

  function setFollowStatus(message) {
    elements.followStatus.textContent = stringValue(message);
  }

  function statusClass(kind) {
    if (kind === "success") {
      return "cr-status--success";
    }
    if (kind === "error") {
      return "cr-status--danger";
    }
    return "cr-status--info";
  }
})();
