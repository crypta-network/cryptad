(function () {
  "use strict";

  const namespace = "sharesite-drafts";
  const key = "dataset";
  const maximumDatasetBytes = 196608;
  const maximumPackageBytes = 524288;
  const revision = "c99ad9c8e83004f904f8ee742ab2861f5751ee3b";
  const encoder = new TextEncoder();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  const clone = (value) => JSON.parse(JSON.stringify(value));
  const empty = () => ({ schemaVersion: 1, operations: [], drafts: [] });
  const fail = () => { throw new Error("draft_validation_failed"); };
  const secret = /(?:bearer\s+[a-z0-9._~-]+|insertssk|private[ _-]?key|\b(?:insertURI|password|secret|token|seed)\s*[:=]|-----BEGIN[^\r\n]*PRIVATE KEY)/i;

  function canonical(value) {
    if (Array.isArray(value)) return value.map(canonical);
    if (value && typeof value === "object") return Object.fromEntries(
      Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
    return value;
  }

  async function digest(value) {
    const bytes = typeof value === "string" ? encoder.encode(value) : value;
    return Array.from(new Uint8Array(await window.crypto.subtle.digest("SHA-256", bytes)),
      (byte) => byte.toString(16).padStart(2, "0")).join("");
  }

  function scanPrivateMaterial(value) {
    if (typeof value === "string") {
      if (secret.test(value)) fail();
      for (const match of value.matchAll(/(?:SSK|USK)@[^\s<>"']*/gi)) {
        const parts = match[0].split(",");
        if (parts.length !== 3) fail();
        let extra;
        try { extra = atob(parts[2].split("/")[0].replace(/~/g, "/").replace(/-/g, "+")); }
        catch (_) { fail(); }
        if (extra.length !== 5 || extra.charCodeAt(1) !== 0) fail();
      }
    } else if (Array.isArray(value)) {
      for (const child of value) scanPrivateMaterial(child);
    } else if (value && typeof value === "object") {
      for (const child of Object.values(value)) scanPrivateMaterial(child);
    }
  }

  function keysOnly(value, keys) {
    if (!value || typeof value !== "object" || Array.isArray(value)
        || Object.keys(value).some((key) => !keys.includes(key))) fail();
  }

  function validateDataset(value) {
    keysOnly(value, ["schemaVersion", "operations", "drafts"]);
    if (!value || value.schemaVersion !== 1 || !Array.isArray(value.drafts)
        || !Array.isArray(value.operations) || value.operations.length > 32
        || encoder.encode(JSON.stringify(value)).length > maximumDatasetBytes) fail();
    const ids = new Set();
    for (const operation of value.operations) {
      keysOnly(operation, ["operationId", "payloadSha256", "status", "draftIds", "originalsSha256"]);
      if (!/^[0-9a-f-]{36}$/.test(operation.operationId || "")
          || !/^[0-9a-f]{64}$/.test(operation.payloadSha256 || "")
          || !/^[0-9a-f]{64}$/.test(operation.originalsSha256 || "")
          || !["committed", "undone"].includes(operation.status)
          || !Array.isArray(operation.draftIds) || operation.draftIds.length > 16) fail();
    }
    for (const draft of value.drafts) {
      keysOnly(draft, ["id", "operationId", "sourceId", "name", "description", "text",
        "historicalEdition", "logicalPath", "publicReadReference"]);
      if (!draft || typeof draft.id !== "string" || ids.has(draft.id)
          || typeof draft.operationId !== "string" || !Number.isSafeInteger(draft.sourceId)
          || draft.sourceId < 0 || typeof draft.text !== "string"
          || encoder.encode(draft.text).length > 65536) fail();
      for (const field of ["name", "description", "logicalPath"]) {
        if (typeof draft[field] !== "string"
            || encoder.encode(draft[field]).length > (field === "description" ? 16384 : 4096)) fail();
      }
      scanPrivateMaterial(draft);
      ids.add(draft.id);
    }
    return value;
  }

  async function parsePackage(bytes) {
    if (bytes.byteLength > maximumPackageBytes) fail();
    const value = JSON.parse(decoder.decode(bytes));
    keysOnly(value, ["format", "privacy", "source", "operationId", "selectedIds", "exclusions", "payload"]);
    keysOnly(value.source, ["repository", "revision", "profile", "snapshotSha256", "provenance", "literalTextSha256"]);
    if (value.format !== "crypta.sharesite-migration.v1" || value.privacy !== "private-user-data"
        || !value.source || value.source.repository !== "hyphanet/plugin-sharesite"
        || value.source.revision !== revision || value.source.profile !== "sharesite-pastebin-v1"
        || !/^[0-9a-f-]{36}$/.test(value.operationId || "")
        || !Array.isArray(value.selectedIds) || value.selectedIds.length < 1
        || value.selectedIds.length > 16 || new Set(value.selectedIds).size !== value.selectedIds.length) fail();
    if (!/^[0-9a-f]{64}$/.test(value.source.snapshotSha256 || "")
        || typeof value.source.provenance !== "string"
        || encoder.encode(value.source.provenance).length > 4096) fail();
    keysOnly(value.exclusions, ["recently_deleted", "unknown_page_field", "malformed_boolean",
      "unsupported_textile", "broken_record", "text_limit", "metadata_limit", "invalid_record",
      "invalid_number", "prohibited_secret_material", "prohibited_or_invalid_key", "invalid_public_reference",
      "not_selected", "private_insert_identity_not_imported", "css_not_imported",
      "external_resource_not_imported", "scheduling_not_imported", "runtime_status_not_imported"]);
    if (Object.values(value.exclusions).some((count) => !Number.isSafeInteger(count) || count < 0 || count > 512)) fail();
    const payload = value.payload;
    keysOnly(payload, ["exportVersion", "appId", "exportedAt", "namespaceCount", "recordCount", "namespaces", "records"]);
    if (!payload || payload.exportVersion !== 1 || payload.appId !== "site-publisher"
        || !Array.isArray(payload.records) || payload.records.length !== 1
        || !Array.isArray(payload.namespaces) || payload.namespaces.length !== 1
        || payload.namespaces[0].namespace !== namespace || payload.namespaces[0].schemaVersion !== 1) fail();
    const metadata = payload.namespaces[0];
    keysOnly(metadata, ["appId", "namespace", "schemaVersion", "recordCount", "totalBytes",
      "createdAt", "updatedAt", "lastMigrationAt", "migrationHistory"]);
    const epoch = "1970-01-01T00:00:00Z";
    if (payload.exportedAt !== epoch || payload.namespaceCount !== 1 || payload.recordCount !== 1
        || metadata.appId !== "site-publisher" || metadata.recordCount !== 1
        || metadata.createdAt !== epoch || metadata.updatedAt !== epoch || metadata.lastMigrationAt !== null
        || !Array.isArray(metadata.migrationHistory) || metadata.migrationHistory.length) fail();
    const record = payload.records[0];
    keysOnly(record, ["namespace", "key", "contentType", "schemaVersion", "valueBytes", "sha256",
      "createdAt", "updatedAt", "valueBase64"]);
    if (record.contentType !== "application/json" || record.createdAt !== epoch || record.updatedAt !== epoch) fail();
    if (record.namespace !== namespace || record.key !== key || record.schemaVersion !== 1
        || typeof record.valueBase64 !== "string" || record.valueBase64.length > 349528) fail();
    const data = Uint8Array.from(atob(record.valueBase64), (character) => character.charCodeAt(0));
    if (record.valueBytes !== data.length || metadata.totalBytes !== data.length
        || record.sha256 !== await digest(data)) fail();
    const dataset = validateDataset(JSON.parse(decoder.decode(data)));
    if (dataset.operations.length || dataset.drafts.length !== value.selectedIds.length) fail();
    const fidelity = value.source.literalTextSha256;
    if (!fidelity || typeof fidelity !== "object" || Array.isArray(fidelity)
        || Object.keys(fidelity).length !== dataset.drafts.length) fail();
    for (const draft of dataset.drafts) {
      if (fidelity[String(draft.sourceId)] !== await digest(draft.text)) fail();
      if (draft.operationId !== value.operationId || !value.selectedIds.includes(draft.sourceId)
          || draft.id !== `${value.operationId}-${draft.sourceId}`) fail();
    }
    scanPrivateMaterial(value);
    return { package: value, dataset, payloadSha256: await digest(bytes) };
  }

  function controller(api) {
    let data = empty();
    let currentSha256 = "absent";
    let pending = null;

    async function requireGuard() {
      const status = await api.data.status();
      if (status.sharesiteWriteGuard !== 1) throw new Error("guarded_daemon_required");
    }

    async function load() {
      await requireGuard();
      try {
        const record = await api.data.records.get(namespace, key);
        data = validateDataset(JSON.parse(record.valueText || decoder.decode(
          Uint8Array.from(atob(record.valueBase64), (c) => c.charCodeAt(0)))));
        currentSha256 = record.sha256;
      } catch (error) {
        if (error && ["app_data_record_not_found", "not_found"].includes(error.code)) {
          data = empty(); currentSha256 = "absent";
        } else throw error;
      }
      pending = null;
      return clone(data);
    }

    async function preview(next, kind) {
      await requireGuard();
      validateDataset(next);
      const valueJson = JSON.stringify(next);
      const request = { namespace, key, schemaVersion: 1, contentType: "application/json",
        valueJson, ifMatchSha256: currentSha256, writeIntent: "preview", writeMode: kind, backupReady: "true" };
      const receipt = await api.data.records.put(request);
      pending = { request, receipt, next: clone(next), kind };
      return { ...receipt, kind, draftCount: next.drafts.length };
    }

    async function previewImport(converted) {
      const entry = data.operations.find((operation) => operation.operationId === converted.package.operationId);
      if (entry) {
        if (entry.payloadSha256 !== converted.payloadSha256) fail();
        if (entry.status !== "committed") throw new Error("import_previously_undone");
        pending = null;
        return { replay: true, kind: "replay" };
      }
      if (data.operations.length >= 32) fail();
      const next = clone(data);
      const drafts = converted.dataset.drafts;
      if (drafts.some((draft) => next.drafts.some((existing) => existing.id === draft.id))) fail();
      next.drafts.push(...clone(drafts));
      next.operations.push({ operationId: converted.package.operationId,
        payloadSha256: converted.payloadSha256, status: "committed",
        draftIds: drafts.map((draft) => draft.id), originalsSha256: await digest(JSON.stringify(canonical(drafts))) });
      return preview(next, "import");
    }

    async function previewEdit(id, text) {
      const next = clone(data);
      const draft = next.drafts.find((entry) => entry.id === id);
      if (!draft) fail();
      draft.text = text;
      return preview(next, "edit");
    }

    async function previewUndo(operationId) {
      const next = clone(data);
      const operation = next.operations.find((entry) => entry.operationId === operationId);
      if (!operation || operation.status !== "committed") fail();
      const drafts = next.drafts.filter((draft) => operation.draftIds.includes(draft.id));
      if (await digest(JSON.stringify(canonical(drafts))) !== operation.originalsSha256) {
        throw new Error("edited_drafts_require_manual_recovery");
      }
      next.drafts = next.drafts.filter((draft) => !operation.draftIds.includes(draft.id));
      operation.status = "undone";
      return preview(next, "undo");
    }

    async function previewRestore(bytes) {
      if (bytes.byteLength > maximumPackageBytes) fail();
      const backup = JSON.parse(decoder.decode(bytes));
      if (backup.format !== "crypta.site-publisher-private-drafts.v1"
          || backup.privacy !== "private-user-data" || backup.encryption.mode !== "none") fail();
      const restored = validateDataset(backup.dataset);
      const next = clone(data);
      for (const operation of restored.operations) {
        const existing = next.operations.find((entry) => entry.operationId === operation.operationId);
        if (existing && JSON.stringify(existing) !== JSON.stringify(operation)) {
          throw new Error("restore_collision_requires_manual_recovery");
        }
        if (!existing) next.operations.push(clone(operation));
      }
      for (const draft of restored.drafts) {
        const existing = next.drafts.find((entry) => entry.id === draft.id);
        if (existing && JSON.stringify(existing) !== JSON.stringify(draft)) {
          throw new Error("restore_collision_requires_manual_recovery");
        }
        if (!existing) next.drafts.push(clone(draft));
      }
      return preview(next, "restore");
    }

    async function commit() {
      await requireGuard();
      if (!pending) fail();
      const candidate = pending;
      const record = await api.data.records.put({ ...candidate.request, writeIntent: "commit",
        writePreviewId: candidate.receipt.previewId });
      data = candidate.next;
      currentSha256 = record.sha256;
      pending = null;
      return clone(data);
    }

    async function publish(id) {
      const draft = data.drafts.find((entry) => entry.id === id);
      if (!draft) fail();
      return api.content.insertPlainText({ text: draft.text,
        identifier: `site-text-${window.crypto.randomUUID()}` });
    }

    return { load, previewImport, previewEdit, previewUndo, previewRestore, commit, publish,
      snapshot: () => clone(data),
      backup: () => JSON.stringify({ format: "crypta.site-publisher-private-drafts.v1",
        privacy: "private-user-data", encryption: { mode: "none" }, dataset: data }) };
  }

  window.SitePublisherDrafts = Object.freeze({ controller, parsePackage, validateDataset });
  document.addEventListener("DOMContentLoaded", start);

  async function start() {
    const panel = document.getElementById("draft-panel");
    if (!panel) return;
    const controls = Object.fromEntries(["file", "list", "text", "preview", "status", "commit",
      "ack", "backup-ack", "publish-ack", "selection", "binding"].map((id) =>
      [id, document.getElementById(`draft-${id}`)]));
    const model = controller(CryptaPlatform);
    let selectedId = "";
    let editorDirty = false;
    let converted = null;
    let prepared = false;
    const status = (message) => { controls.status.textContent = message; };
    const on = (id, action) => document.getElementById(`draft-${id}`).addEventListener("click", async () => {
      try {
        if (["inspect", "save", "undo", "restore"].includes(id) && !controls["backup-ack"].checked) {
          status("Download and retain a private target backup, then acknowledge backup readiness before preview.");
          return;
        }
        await action();
      } catch (_) {
        prepared = false; controls.commit.disabled = true;
        status("Draft action could not complete. Refresh and preview again. Edited drafts or collisions require private manual recovery; no publication was requested by import or save.");
      }
    });
    function render() {
      const drafts = model.snapshot().drafts;
      controls.list.replaceChildren();
      for (const draft of drafts) {
        const option = document.createElement("option");
        option.value = draft.id; option.textContent = draft.name || `Page ${draft.sourceId}`;
        controls.list.append(option);
      }
      if (!drafts.some((draft) => draft.id === selectedId)) selectedId = drafts[0]?.id || "";
      controls.list.value = selectedId;
      showSelected();
    }
    function showSelected() {
      editorDirty = false;
      const draft = model.snapshot().drafts.find((entry) => entry.id === selectedId);
      controls.text.value = draft?.text || "";
      controls.preview.textContent = draft?.text || "";
      controls["publish-ack"].checked = false;
    }
    async function showPlan(result) {
      prepared = !result.replay;
      controls.commit.disabled = !prepared;
      controls.ack.checked = false;

      controls.binding.textContent = result.replay ? "Completed import replay: no changes."
        : JSON.stringify(result, null, 2);
      status(result.replay ? "This exact import is already committed; no drafts or publication added."
        : "Private preview ready. Download a separate target backup, review this change, then acknowledge and commit.");
    }
    controls.list.addEventListener("change", () => {
      selectedId = controls.list.value; prepared = false; controls.commit.disabled = true;
      showSelected();
    });
    controls.text.addEventListener("input", () => {
      editorDirty = true;
      controls.preview.textContent = controls.text.value;
      controls["publish-ack"].checked = false;
      prepared = false; controls.commit.disabled = true;
    });
    on("inspect", async () => {
      const file = controls.file.files[0];
      if (!file || file.size > maximumPackageBytes) fail();
      converted = await parsePackage(new Uint8Array(await file.arrayBuffer()));
      controls.selection.textContent = JSON.stringify({ selectedIds: converted.package.selectedIds,
        pages: converted.dataset.drafts.map((draft) => ({ sourceId: draft.sourceId,
          name: draft.name, description: draft.description, text: draft.text })),
        exclusions: converted.package.exclusions }, null, 2);
      await showPlan(await model.previewImport(converted));
    });
    on("save", async () => {
      const saved = model.snapshot().drafts.find((entry) => entry.id === selectedId);
      if (!saved) fail();
      await showPlan(await model.previewEdit(selectedId, editorDirty ? controls.text.value : saved.text));
    });
    on("undo", async () => {
      const draft = model.snapshot().drafts.find((entry) => entry.id === selectedId);
      if (!draft) fail();
      await showPlan(await model.previewUndo(draft.operationId));
    });
    on("restore", async () => {
      const file = controls.file.files[0];
      if (!file || file.size > maximumPackageBytes) fail();
      await showPlan(await model.previewRestore(new Uint8Array(await file.arrayBuffer())));
    });
    on("commit", async () => {
      if (!prepared || !controls.ack.checked || !controls["backup-ack"].checked) fail();
      await model.commit(); prepared = false; controls.commit.disabled = true;
      render(); status("Draft change committed locally. No network publication was queued.");
    });
    on("backup", async () => {
      const blob = new Blob([model.backup()], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url; link.download = "site-publisher-private-drafts.json";
      link.click(); URL.revokeObjectURL(url);
      status("Private target backup download requested. Keep it separate from the old source snapshot; it is not encrypted.");
    });
    on("refresh", async () => { await model.load(); prepared = false; controls.commit.disabled = true; render(); status("Durable drafts refreshed."); });
    on("publish", async () => {
      if (!controls["publish-ack"].checked) fail();
      const draft = model.snapshot().drafts.find((entry) => entry.id === selectedId);
      if (!draft || editorDirty) fail();
      await model.publish(selectedId); controls["publish-ack"].checked = false;
      status("Saved literal text queued for a new CHK address. Inspect the upload queue for completion. Local undo cannot remove published content.");
    });
    try {
      await CryptaPlatform.bootstrap.load({ appId: "site-publisher" });
      await model.load(); render(); status("Private durable drafts ready. Import and save never publish.");
    } catch (_) { status("Draft storage unavailable. Approve the signed app update and its data permissions, then refresh."); }
  }
})();
