(function () {
  "use strict";

  const appId = "social-inbox";
  const socialMessageType = "crypta.social.message.v1";
  const socialOutboxType = "crypta.social.outbox.v1";
  const socialOutboxContentType = "application/vnd.crypta.social.outbox+json";
  const socialOutboxTargetFilename = "social-outbox.json";
  const maxSources = 16;
  const maxImportedMessages = 160;
  const maxLocalOutboxMessages = 24;
  const maxReadStateEntries = 240;
  const maxDraftBodyLength = 4096;
  const maxImportedSubjectLength = 160;
  const maxImportedChannelLength = 64;
  const maxMessageReferenceLength = 512;
  const maxRecipientFingerprintLength = 128;
  const maxAuthorLabelLength = 80;
  const maxProfileUriLength = 512;
  const maxTagCount = 12;
  const maxTagLength = 32;
  const maxImportedBodyPreviewLength = 700;
  const maxFetchedDocumentChars = 128 * 1024;
  const sourcePollIntervalSeconds = 15 * 60;
  const dataSchemaVersion = 1;

  const records = {
    uiState: ["ui-state", "social-inbox"],
    sources: ["social", "sources"],
    outboxSummary: ["social", "outbox-summary"],
    importedMessageIndex: ["social", "imported-message-index"],
    readState: ["social", "read-state"],
    drafts: ["social", "drafts"],
  };

  const state = {
    identities: [],
    selectedIdentityId: "",
    localOutbox: [],
    sources: [],
    subscriptions: [],
    importedMessages: [],
    readState: {},
    drafts: {},
    outboxSummary: null,
    trustScores: {},
  };

  const elements = {
    composeForm: document.getElementById("compose-form"),
    identityForm: document.getElementById("identity-form"),
    identitySelect: document.getElementById("identity-select"),
    identitySummary: document.getElementById("identity-summary"),
    inboxList: document.getElementById("inbox-list"),
    outboxList: document.getElementById("outbox-list"),
    prepareProfileButton: document.getElementById("prepare-profile-button"),
    profileForm: document.getElementById("profile-form"),
    profilePreview: document.getElementById("profile-preview"),
    publishForm: document.getElementById("publish-form"),
    publishSummary: document.getElementById("publish-summary"),
    queuePreview: document.getElementById("queue-preview"),
    refreshIdentitiesButton: document.getElementById("refresh-identities-button"),
    refreshQueueButton: document.getElementById("refresh-queue-button"),
    refreshSubscriptionsButton: document.getElementById("refresh-subscriptions-button"),
    refreshTrustButton: document.getElementById("refresh-trust-button"),
    sourceForm: document.getElementById("source-form"),
    sourceList: document.getElementById("source-list"),
    status: document.getElementById("status"),
    subscriptionList: document.getElementById("subscription-list"),
  };

  document.addEventListener("DOMContentLoaded", start);

  async function start() {
    bindControls();
    try {
      await CryptaPlatform.bootstrap.load({ appId });
      await loadDurableState();
      restoreDrafts();
      await refreshIdentities({ silent: true });
      await refreshSubscriptions({ silent: true });
      renderAll();
      await refreshUploadQueue({ silent: true });
    } catch (error) {
      setStatus(CryptaPlatform.api.errorMessage(error), "error");
    }
  }

  function bindControls() {
    elements.identityForm.addEventListener("submit", createIdentity);
    elements.identitySelect.addEventListener("change", selectIdentity);
    elements.prepareProfileButton.addEventListener("click", prepareProfileDocument);
    elements.composeForm.addEventListener("submit", signMessage);
    elements.publishForm.addEventListener("submit", publishOutbox);
    elements.sourceForm.addEventListener("submit", addSource);
    elements.refreshIdentitiesButton.addEventListener("click", refreshIdentities);
    elements.refreshQueueButton.addEventListener("click", refreshUploadQueue);
    elements.refreshSubscriptionsButton.addEventListener("click", refreshSubscriptions);
    elements.refreshTrustButton.addEventListener("click", refreshTrustAnnotations);
  }

  async function createIdentity(event) {
    event.preventDefault();
    const label = fieldValue(elements.identityForm, "identityLabel") || "Social Inbox identity";
    try {
      setStatus("Creating AppVault identity...");
      await CryptaPlatform.vault.identities.create({
        label,
        scopes: ["metadata.read", "sign.domain-separated"],
      });
      elements.identityForm.reset();
      await refreshIdentities({ silent: true });
      setStatus("Preview identity created.");
    } catch (error) {
      setStatus(CryptaPlatform.api.errorMessage(error), "error");
    }
  }

  async function refreshIdentities(options) {
    try {
      const response = await CryptaPlatform.vault.identities.list();
      state.identities = boundedArray(response.identities || response, 50);
      if (!selectedIdentity()) {
        state.selectedIdentityId = identityId(state.identities[0]) || "";
      }
      await persistUiState();
      renderIdentities();
      if (!(options && options.silent)) {
        setStatus("Identity metadata refreshed.");
      }
    } catch (error) {
      if (!(options && options.silent)) {
        setStatus(CryptaPlatform.api.errorMessage(error), "error");
      }
    }
  }

  async function selectIdentity() {
    state.selectedIdentityId = elements.identitySelect.value;
    await persistUiState();
    renderIdentities();
  }

  async function prepareProfileDocument() {
    const identity = selectedIdentity();
    if (!identity) {
      setStatus("Select or create an identity first.", "error");
      return;
    }
    const formData = new FormData(elements.profileForm);
    const displayName = textValue(formData, "displayName") || textValue(formData, "authorLabel");
    if (!displayName) {
      setStatus("Profile document display name is required.", "error");
      return;
    }
    try {
      const profileDocument = await CryptaPlatform.vault.identities.createProfileDocument(
        identityId(identity),
        {
          displayName,
          website: textValue(formData, "profileUri"),
          contactUri: textValue(formData, "profileUri"),
          tags: ["social-inbox", "preview"],
        }
      );
      elements.profilePreview.textContent = JSON.stringify(profileDocument, null, 2);
      state.drafts.profileUri = textValue(formData, "profileUri");
      state.drafts.authorLabel = textValue(formData, "authorLabel");
      await persistDrafts();
      setStatus("Signed profile document prepared.");
    } catch (error) {
      setStatus(CryptaPlatform.api.errorMessage(error), "error");
    }
  }

  async function signMessage(event) {
    event.preventDefault();
    const identity = selectedIdentity();
    if (!identity) {
      setStatus("Select or create an identity first.", "error");
      return;
    }
    const formData = new FormData(elements.composeForm);
    const message = messageDraftFromForm(formData);
    if (!message.body) {
      setStatus("Message body is required.", "error");
      return;
    }
    if (message.body.length > maxDraftBodyLength) {
      setStatus("Message body is too large for the preview signer.", "error");
      return;
    }
    try {
      setStatus("Signing message through AppVault...");
      const response = await CryptaPlatform.vault.identities.createSocialMessageDocument(
        identityId(identity),
        message
      );
      const signedMessage = signedSocialMessageFromResponse(response);
      ensureSignedSocialMessage(signedMessage);
      state.localOutbox.unshift(signedMessage);
      state.localOutbox = state.localOutbox.slice(0, maxLocalOutboxMessages);
      if (checkboxValue(elements.composeForm, "persistDraft")) {
        state.drafts.message = boundedDraft(message);
      } else {
        delete state.drafts.message;
      }
      await persistDrafts();
      await persistOutboxSummary(await localOutboxSummary());
      renderOutbox();
      renderPublishSummary();
      setStatus("Message signed and added to the local outbox.");
    } catch (error) {
      setStatus(CryptaPlatform.api.errorMessage(error), "error");
    }
  }

  async function publishOutbox(event) {
    event.preventDefault();
    if (state.localOutbox.length === 0) {
      setStatus("Sign at least one message before publishing an outbox snapshot.", "error");
      return;
    }
    const formData = new FormData(elements.publishForm);
    const insertUri = textValue(formData, "insertUri");
    const identifier = textValue(formData, "identifier") || generatedId("social-outbox");
    const publicSourceUri = textValue(formData, "publicSourceUri");
    const sourceLabel = textValue(formData, "sourceLabel") || "Social Inbox Preview";
    const document = {
      type: socialOutboxType,
      appId,
      generatedAt: new Date().toISOString(),
      profileUri: fieldValue(elements.profileForm, "profileUri"),
      sourceLabel,
      messages: state.localOutbox.slice(0, maxLocalOutboxMessages),
    };
    try {
      setStatus("Queueing generated outbox document...");
      const documentSha256 = await sha256Hex(JSON.stringify(document));
      const publicSourceUriHash = publicSourceUri ? await sha256Hex(publicSourceUri) : "";
      const response = await CryptaPlatform.content.insertAppDocument({
        insertUri,
        identifier,
        document,
        contentType: socialOutboxContentType,
        targetFilename: socialOutboxTargetFilename,
      });
      const summary = {
        publishedAt: new Date().toISOString(),
        status: "queued",
        identifier,
        targetFilename: socialOutboxTargetFilename,
        contentType: socialOutboxContentType,
        messageCount: document.messages.length,
        documentSha256,
        publicSourceUriSummary: redactedPublicUri(publicSourceUri),
        publicSourceUriHash,
        queueRequestId: stringField(response, "requestId", "identifier", "id"),
        insertUriRedaction: "private insert URI accepted and not stored",
      };
      await persistOutboxSummary(summary);
      elements.publishForm.reset();
      renderPublishSummary(redactedInsertUri(insertUri));
      await refreshUploadQueue({ silent: true });
      setStatus("Outbox snapshot queued without storing the private insert URI.");
    } catch (error) {
      setStatus(CryptaPlatform.api.errorMessage(error), "error");
    }
  }

  async function addSource(event) {
    event.preventDefault();
    if (state.sources.length >= maxSources) {
      setStatus("Source limit reached for this preview app.", "error");
      return;
    }
    const formData = new FormData(elements.sourceForm);
    const uri = textValue(formData, "uri");
    if (!isSocialSourceUri(uri)) {
      setStatus("Social sources must start with USK@ or crypta:USK@.", "error");
      return;
    }
    const uriHash = await sha256Hex(uri);
    const source = {
      id: generatedId("source"),
      label: textValue(formData, "label") || "Social source",
      uriHash,
      uriSummary: redactedPublicUri(uri),
      subscriptionId: "",
      lastCheckedAt: "",
      lastStatus: "Not fetched",
      lastSeenEdition: "",
      lastSeenResolvedUriSummary: "",
      updateCount: 0,
      lastError: "",
    };
    try {
      const subscription = await CryptaPlatform.content.subscriptions.create({
        uri,
        label: source.label,
        pollIntervalSeconds: sourcePollIntervalSeconds,
        maxBytes: maxFetchedDocumentChars,
        timeoutMillis: 30000,
      });
      source.subscriptionId = subscriptionId(subscription.subscription || subscription);
      source.lastStatus = "Subscribed";
      state.subscriptions = boundedArray(
        [subscription.subscription || subscription].concat(state.subscriptions),
        80
      );
      state.sources.unshift(source);
      state.sources = state.sources.slice(0, maxSources);
      elements.sourceForm.reset();
      await persistSources();
      await refreshSubscriptions({ silent: true });
      renderSources();
      renderSubscriptions();
      setStatus("Social source subscribed.");
    } catch (error) {
      setStatus(CryptaPlatform.api.errorMessage(error), "error");
    }
  }

  async function refreshSubscriptions(options) {
    try {
      const response = await CryptaPlatform.content.subscriptions.list();
      state.subscriptions = boundedArray(response.subscriptions || response, 80);
      syncSourceSubscriptionMetadata();
      await persistSources();
      renderSources();
      renderSubscriptions();
      if (!(options && options.silent)) {
        setStatus("Subscription metadata refreshed.");
      }
    } catch (error) {
      if (!(options && options.silent)) {
        setStatus(CryptaPlatform.api.errorMessage(error), "error");
      }
    }
  }

  async function refreshUploadQueue(options) {
    try {
      const response = await CryptaPlatform.queue.snapshot({ page: "uploads" });
      renderQueue(response);
      if (!(options && options.silent)) {
        setStatus("Queue summary refreshed.");
      }
    } catch (error) {
      if (!(options && options.silent)) {
        setStatus(CryptaPlatform.api.errorMessage(error), "error");
      }
    }
  }

  async function refreshSource(sourceId) {
    const source = state.sources.find((item) => item.id === sourceId);
    if (!source) {
      return;
    }
    try {
      source.lastCheckedAt = new Date().toISOString();
      source.lastStatus = "Fetching";
      renderSources();
      const fetchUri = sourceFetchUri(source);
      if (!fetchUri) {
        throw new Error("Refresh subscriptions before fetching this source.");
      }
      const response = await CryptaPlatform.content.fetchText({
        uri: fetchUri,
        maxBytes: maxFetchedDocumentChars,
        timeoutMillis: 30000,
        purpose: "social-outbox",
      });
      await importOutboxText(fetchedTextFromResponse(response), source, response);
      source.lastStatus = "Imported";
      source.lastSeenResolvedUriSummary =
        redactedPublicUri(stringField(response, "resolvedUri", "finalUri")) ||
        source.lastSeenResolvedUriSummary;
      source.updateCount += 1;
      source.lastError = "";
      await persistSources();
      renderAll();
      await refreshTrustAnnotations({ silent: true });
      setStatus("Social source imported.");
    } catch (error) {
      source.lastStatus = "Error";
      source.lastError = CryptaPlatform.api.errorMessage(error);
      await persistSources();
      renderSources();
      setStatus(source.lastError, "error");
    }
  }

  async function mutateSubscription(subscriptionIdValue, action) {
    try {
      if (action === "refresh") {
        await CryptaPlatform.content.subscriptions.refresh(subscriptionIdValue);
      } else if (action === "pause") {
        await CryptaPlatform.content.subscriptions.pause(subscriptionIdValue);
      } else if (action === "resume") {
        await CryptaPlatform.content.subscriptions.resume(subscriptionIdValue);
      } else if (action === "remove") {
        await CryptaPlatform.content.subscriptions.remove(subscriptionIdValue);
        state.sources = state.sources.map((source) =>
          source.subscriptionId === subscriptionIdValue
            ? Object.assign({}, source, { subscriptionId: "", lastStatus: "Subscription removed" })
            : source
        );
        await persistSources();
      }
      await refreshSubscriptions({ silent: true });
      setStatus("Subscription updated.");
    } catch (error) {
      setStatus(CryptaPlatform.api.errorMessage(error), "error");
    }
  }

  async function importOutboxText(text, source, response) {
    const value = typeof text === "string" ? text : "";
    if (value.length > maxFetchedDocumentChars) {
      throw new Error("Social outbox document is too large.");
    }
    const document = parseJsonObject(value, "Social outbox");
    if (document.type !== socialOutboxType || document.appId !== appId) {
      throw new Error("Social outbox document type is not supported.");
    }
    if (!Array.isArray(document.messages)) {
      throw new Error("Social outbox messages must be an array.");
    }
    if (document.messages.length > maxLocalOutboxMessages) {
      throw new Error("Social outbox message count exceeds the preview limit.");
    }
    const normalized = [];
    for (const signedMessage of document.messages) {
      normalized.push(await normalizeImportedMessage(signedMessage, source, response));
    }
    mergeImportedMessages(normalized);
    await persistImportedMessages();
  }

  async function normalizeImportedMessage(signedMessage, source, response) {
    ensureSignedSocialMessage(signedMessage);
    await verifySocialMessageSignature(signedMessage);
    const message = signedMessage.message;
    const signature = signedMessage.signature;
    const body = rawString(message.body);
    const messageId = stringValue(message.messageId) || (await sha256Hex(JSON.stringify(message)));
    return {
      messageId,
      authorFingerprint: stringValue(message.authorFingerprint),
      authorLabel: stringValue(message.authorLabel),
      profileUri: stringValue(message.profileUri),
      channel: stringValue(message.channel) || "general",
      subject: boundedPreview(stringValue(message.subject), 180),
      bodyPreview: boundedPreview(body, maxImportedBodyPreviewLength),
      bodySha256: await sha256Hex(body),
      createdAt: stringValue(message.createdAt),
      replyTo: stringValue(message.replyTo),
      sourceId: source.id,
      sourceLabel: source.label,
      sourceUriHash: source.uriHash || (await sha256Hex(source.subscriptionId || source.id)),
      resolvedUri: redactedPublicUri(stringField(response, "resolvedUri", "requestedUri")),
      signatureSha256: await sha256Hex(stringValue(signature.signatureBase64)),
      importedAt: new Date().toISOString(),
    };
  }

  function ensureSignedSocialMessage(signedMessage) {
    const source = parsePlainObject(signedMessage, "Signed social message");
    const message = parsePlainObject(source.message, "Social message payload");
    const signature = parsePlainObject(source.signature, "Social message signature");
    rejectUnexpectedFields(source, ["type", "message", "signature"], "Signed social message");
    rejectUnexpectedFields(
      message,
      [
        "appId",
        "identityId",
        "authorFingerprint",
        "authorLabel",
        "profileUri",
        "messageId",
        "createdAt",
        "channel",
        "subject",
        "body",
        "format",
        "replyTo",
        "recipientFingerprint",
        "tags",
      ],
      "Social message payload"
    );
    rejectUnexpectedFields(
      signature,
      [
        "algorithm",
        "domain",
        "payloadHash",
        "publicKeyFingerprint",
        "publicKeyBase64",
        "signatureBase64",
      ],
      "Social message signature"
    );
    if (source.type !== socialMessageType) {
      throw new Error("Social message type is not supported.");
    }
    if (message.appId !== appId) {
      throw new Error("Social message app id is not supported.");
    }
    if (signature.domain !== socialMessageType) {
      throw new Error("Social message signature domain is not supported.");
    }
    if (signature.algorithm !== "Ed25519") {
      throw new Error("Social message signature algorithm is not supported.");
    }
    for (const name of [
      "appId",
      "identityId",
      "messageId",
      "authorFingerprint",
      "createdAt",
      "channel",
      "body",
      "format",
    ]) {
      if (typeof message[name] !== "string" || !stringValue(message[name])) {
        throw new Error(`Social message ${name} is required.`);
      }
    }
    requireIsoTimestamp(message.createdAt, "createdAt");
    requireBoundedText(message.authorFingerprint, maxRecipientFingerprintLength, "authorFingerprint");
    requireBoundedText(message.identityId, maxMessageReferenceLength, "identityId");
    requireBoundedText(message.messageId, maxMessageReferenceLength, "messageId");
    requireBoundedText(message.channel, maxImportedChannelLength, "channel");
    requireBoundedText(message.subject, maxImportedSubjectLength, "subject");
    requireBoundedText(message.authorLabel, maxAuthorLabelLength, "authorLabel");
    requireBoundedText(message.profileUri, maxProfileUriLength, "profileUri");
    requireBoundedText(message.replyTo, maxMessageReferenceLength, "replyTo");
    requireBoundedText(message.recipientFingerprint, maxRecipientFingerprintLength, "recipientFingerprint");
    if (message.format !== "text/plain") {
      throw new Error("Social message format must be text/plain.");
    }
    if (rawString(message.body).length > maxDraftBodyLength) {
      throw new Error("Social message body is too large.");
    }
    requireNoUnsafeControls(rawString(message.body), "body", true);
    validateTags(message.tags);
    for (const name of [
      "algorithm",
      "domain",
      "payloadHash",
      "publicKeyFingerprint",
      "publicKeyBase64",
      "signatureBase64",
    ]) {
      if (!stringValue(signature[name])) {
        throw new Error(`Social message signature ${name} is required.`);
      }
    }
    if (signature.publicKeyFingerprint !== message.authorFingerprint) {
      throw new Error("Social message signature fingerprint does not match author.");
    }
    if (!/^[0-9a-f]{64}$/.test(stringValue(signature.payloadHash))) {
      throw new Error("Social message payload hash is malformed.");
    }
    decodeBase64(signature.publicKeyBase64, "publicKeyBase64");
    decodeBase64(signature.signatureBase64, "signatureBase64");
  }

  async function verifySocialMessageSignature(signedMessage) {
    const message = signedMessage.message;
    const signature = signedMessage.signature;
    const canonicalPayload = canonicalSocialMessagePayload(message);
    const payloadHash = await sha256Hex(canonicalPayload);
    if (payloadHash !== stringValue(signature.payloadHash)) {
      throw new Error("Social message payload hash does not match.");
    }
    if (!window.crypto || !window.crypto.subtle) {
      throw new Error("Social message signature verification is unavailable.");
    }
    const publicKeyBytes = decodeBase64(signature.publicKeyBase64, "publicKeyBase64");
    const publicKeyFingerprint = await sha256Hex(publicKeyBytes);
    if (publicKeyFingerprint !== stringValue(signature.publicKeyFingerprint)) {
      throw new Error("Social message public key fingerprint does not match key.");
    }
    try {
      const publicKey = await window.crypto.subtle.importKey(
        "spki",
        publicKeyBytes,
        { name: "Ed25519" },
        false,
        ["verify"]
      );
      const verified = await window.crypto.subtle.verify(
        { name: "Ed25519" },
        publicKey,
        decodeBase64(signature.signatureBase64, "signatureBase64"),
        new TextEncoder().encode(canonicalPayload)
      );
      if (!verified) {
        throw new Error("Social message signature did not verify.");
      }
    } catch (error) {
      throw new Error("Social message signature did not verify.");
    }
  }

  function canonicalSocialMessagePayload(message) {
    const payload = {
      appId: rawString(message.appId),
      identityId: rawString(message.identityId),
      authorFingerprint: rawString(message.authorFingerprint),
    };
    appendOptionalCanonicalField(payload, "authorLabel", message.authorLabel);
    appendOptionalCanonicalField(payload, "profileUri", message.profileUri);
    payload.messageId = rawString(message.messageId);
    payload.createdAt = rawString(message.createdAt);
    payload.channel = rawString(message.channel);
    payload.subject = rawString(message.subject);
    payload.body = rawString(message.body);
    payload.format = "text/plain";
    appendOptionalCanonicalField(payload, "replyTo", message.replyTo);
    appendOptionalCanonicalField(payload, "recipientFingerprint", message.recipientFingerprint);
    if (Array.isArray(message.tags) && message.tags.length > 0) {
      payload.tags = message.tags.map((tag) => stringValue(tag));
    }
    return `${socialMessageType}\n${JSON.stringify({ type: socialMessageType, message: payload })}`;
  }

  function appendOptionalCanonicalField(target, name, value) {
    const text = rawString(value);
    if (text) {
      target[name] = text;
    }
  }

  function rejectUnexpectedFields(object, allowedFields, description) {
    const allowed = new Set(allowedFields);
    for (const field of Object.keys(object)) {
      if (!allowed.has(field)) {
        throw new Error(`${description} field ${field} is not supported.`);
      }
    }
  }

  function requireIsoTimestamp(value, name) {
    const text = stringValue(value);
    if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(text)) {
      throw new Error(`Social message ${name} must be an ISO-8601 UTC timestamp.`);
    }
    const parsed = Date.parse(text);
    if (!Number.isFinite(parsed)) {
      throw new Error(`Social message ${name} must be an ISO-8601 UTC timestamp.`);
    }
  }

  function requireBoundedText(value, maxLength, name) {
    if (value === undefined || value === null) {
      return;
    }
    if (typeof value !== "string") {
      throw new Error(`Social message ${name} must be text.`);
    }
    const text = stringValue(value);
    if (text.length > maxLength) {
      throw new Error(`Social message ${name} is too long.`);
    }
    requireNoUnsafeControls(text, name, false);
  }

  function requireNoUnsafeControls(value, name, allowNormalWhitespace) {
    for (let index = 0; index < value.length; index += 1) {
      const code = value.charCodeAt(index);
      const isNormalWhitespace = code === 0x09 || code === 0x0a || code === 0x0d;
      if ((code < 0x20 || code === 0x7f) && !(allowNormalWhitespace && isNormalWhitespace)) {
        throw new Error(`Social message ${name} contains unsupported control characters.`);
      }
    }
  }

  function validateTags(tags) {
    if (tags === undefined) {
      return;
    }
    if (!Array.isArray(tags)) {
      throw new Error("Social message tags must be an array.");
    }
    if (tags.length > maxTagCount) {
      throw new Error("Social message contains too many tags.");
    }
    for (const tag of tags) {
      const text = stringValue(tag);
      if (!text || text.length > maxTagLength) {
        throw new Error("Social message tag is malformed.");
      }
      requireNoUnsafeControls(text, "tag", false);
    }
  }

  function decodeBase64(value, name) {
    const text = stringValue(value);
    if (
      !text ||
      text.length % 4 !== 0 ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(text)
    ) {
      throw new Error(`Social message signature ${name} is malformed.`);
    }
    try {
      const binary = window.atob(text);
      const bytes = new Uint8Array(binary.length);
      for (let index = 0; index < binary.length; index += 1) {
        bytes[index] = binary.charCodeAt(index);
      }
      return bytes;
    } catch (error) {
      throw new Error(`Social message signature ${name} is malformed.`);
    }
  }

  function signedSocialMessageFromResponse(response) {
    let current = response;
    for (let depth = 0; depth < 4; depth += 1) {
      if (current && typeof current === "object" && !Array.isArray(current)) {
        if (current.type === socialMessageType) {
          return current;
        }
        if (
          current.socialMessage &&
          typeof current.socialMessage === "object" &&
          !Array.isArray(current.socialMessage)
        ) {
          current = current.socialMessage;
          continue;
        }
      }
      break;
    }
    return response;
  }

  function mergeImportedMessages(messages) {
    const byId = new Map();
    for (const existing of state.importedMessages) {
      byId.set(existing.messageId, existing);
    }
    for (const message of messages) {
      byId.set(message.messageId, message);
    }
    state.importedMessages = Array.from(byId.values())
      .sort((left, right) => stringValue(right.createdAt).localeCompare(stringValue(left.createdAt)))
      .slice(0, maxImportedMessages);
  }

  async function refreshTrustAnnotations(options) {
    const fingerprints = uniqueFingerprints();
    if (fingerprints.length === 0) {
      if (!(options && options.silent)) {
        setStatus("No message authors to score.");
      }
      return;
    }
    for (const fingerprint of fingerprints) {
      try {
        const score = await CryptaPlatform.trust.score({
          subjectKind: "identity",
          subjectUri: fingerprint,
          context: "message-author",
          includeEvidence: true,
        });
        state.trustScores[fingerprint] = normalizeTrustScore(score);
      } catch (error) {
        state.trustScores[fingerprint] = {
          status: "unscored",
          summary: CryptaPlatform.api.errorMessage(error),
        };
      }
    }
    renderInbox();
    if (!(options && options.silent)) {
      setStatus("Trust annotations refreshed.");
    }
  }

  function uniqueFingerprints() {
    const values = new Set();
    for (const message of state.importedMessages) {
      if (message.authorFingerprint) {
        values.add(message.authorFingerprint);
      }
    }
    for (const signedMessage of state.localOutbox) {
      const fingerprint = stringValue(signedMessage.message && signedMessage.message.authorFingerprint);
      if (fingerprint) {
        values.add(fingerprint);
      }
    }
    return Array.from(values).slice(0, 80);
  }

  async function loadDurableState() {
    const uiState = await readAppDataRecord(records.uiState, {});
    state.selectedIdentityId = stringValue(uiState.selectedIdentityId);
    state.sources = boundedArray(await readAppDataRecord(records.sources, []), maxSources);
    state.outboxSummary = await readAppDataRecord(records.outboxSummary, null);
    state.importedMessages = boundedArray(
      await readAppDataRecord(records.importedMessageIndex, []),
      maxImportedMessages
    );
    state.readState = boundedObject(
      await readAppDataRecord(records.readState, {}),
      maxReadStateEntries
    );
    state.drafts = await readAppDataRecord(records.drafts, {});
  }

  async function readAppDataRecord(record, fallback) {
    try {
      return await CryptaPlatform.data.records.getJson(record[0], record[1]);
    } catch (error) {
      return fallback;
    }
  }

  async function persistUiState() {
    await putJsonRecord(records.uiState, {
      selectedIdentityId: state.selectedIdentityId,
      updatedAt: new Date().toISOString(),
    });
  }

  async function persistSources() {
    state.sources = boundedSources(state.sources);
    await putJsonRecord(records.sources, state.sources);
  }

  async function persistOutboxSummary(summary) {
    state.outboxSummary = summary;
    await putJsonRecord(records.outboxSummary, summary || {});
  }

  async function persistImportedMessages() {
    state.importedMessages = state.importedMessages.slice(0, maxImportedMessages);
    await putJsonRecord(records.importedMessageIndex, state.importedMessages);
  }

  async function persistReadState() {
    state.readState = boundedObject(state.readState, maxReadStateEntries);
    await putJsonRecord(records.readState, state.readState);
  }

  async function persistDrafts() {
    await putJsonRecord(records.drafts, boundedDrafts(state.drafts));
  }

  async function putJsonRecord(record, value) {
    await CryptaPlatform.data.records.putJson({
      namespace: record[0],
      key: record[1],
      schemaVersion: dataSchemaVersion,
      value,
    });
  }

  function restoreDrafts() {
    if (state.drafts.profileUri) {
      setFieldValue(elements.profileForm, "profileUri", state.drafts.profileUri);
    }
    if (state.drafts.authorLabel) {
      setFieldValue(elements.profileForm, "authorLabel", state.drafts.authorLabel);
    }
    if (state.drafts.message && typeof state.drafts.message === "object") {
      setFieldValue(elements.composeForm, "channel", state.drafts.message.channel || "general");
      setFieldValue(elements.composeForm, "subject", state.drafts.message.subject || "");
      setFieldValue(elements.composeForm, "body", state.drafts.message.body || "");
      setFieldValue(elements.composeForm, "replyTo", state.drafts.message.replyTo || "");
      setFieldValue(
        elements.composeForm,
        "recipientFingerprint",
        state.drafts.message.recipientFingerprint || ""
      );
      setFieldValue(elements.composeForm, "tags", (state.drafts.message.tags || []).join(", "));
    }
  }

  function renderAll() {
    renderIdentities();
    renderSources();
    renderSubscriptions();
    renderOutbox();
    renderPublishSummary();
    renderInbox();
  }

  function renderIdentities() {
    elements.identitySelect.replaceChildren();
    for (const identity of state.identities) {
      const option = document.createElement("option");
      option.value = identityId(identity);
      option.textContent = identityLabel(identity);
      elements.identitySelect.append(option);
    }
    elements.identitySelect.value = state.selectedIdentityId;
    const identity = selectedIdentity();
    elements.identitySummary.replaceChildren();
    if (!identity) {
      elements.identitySummary.append(empty("Create or grant an AppVault identity first."));
      return;
    }
    elements.identitySummary.append(
      summaryRow("Identity", identityId(identity)),
      summaryRow("Fingerprint", stringField(identity, "fingerprint", "publicKeyFingerprint")),
      summaryRow("Kind", stringField(identity, "kind")),
      summaryRow("Label", identityLabel(identity))
    );
  }

  function renderOutbox() {
    elements.outboxList.replaceChildren();
    if (state.localOutbox.length === 0) {
      elements.outboxList.append(empty("Sign a message to stage a local outbox snapshot."));
      return;
    }
    for (const signedMessage of state.localOutbox) {
      const message = signedMessage.message || {};
      const card = document.createElement("article");
      card.className = "message-card";
      card.append(
        headingText(stringValue(message.subject) || "(no subject)", "h3"),
        paragraph("message-meta", `Message ${stringValue(message.messageId)}`),
        paragraph("message-meta", `Author ${stringValue(message.authorFingerprint)}`),
        paragraph("message-body", stringValue(message.body)),
        badges([
          "local outbox",
          stringValue(message.channel) || "general",
          `domain ${socialMessageType}`,
        ])
      );
      elements.outboxList.append(card);
    }
  }

  function renderPublishSummary(ephemeralRedaction) {
    elements.publishSummary.replaceChildren();
    if (!state.outboxSummary) {
      elements.publishSummary.append(empty("Publication status appears after queueing an outbox."));
      return;
    }
    const rows = [
      summaryRow("Status", stringValue(state.outboxSummary.status)),
      summaryRow("Identifier", stringValue(state.outboxSummary.identifier)),
      summaryRow("Target filename", stringValue(state.outboxSummary.targetFilename)),
      summaryRow("Message count", String(state.outboxSummary.messageCount || 0)),
      summaryRow("Document SHA-256", stringValue(state.outboxSummary.documentSha256)),
      summaryRow("Public source URI", stringValue(state.outboxSummary.publicSourceUriSummary)),
      summaryRow("Public source URI SHA-256", stringValue(state.outboxSummary.publicSourceUriHash)),
      summaryRow("Queue request", stringValue(state.outboxSummary.queueRequestId)),
    ];
    if (ephemeralRedaction) {
      rows.push(summaryRow("Insert URI", ephemeralRedaction));
    }
    const section = document.createElement("div");
    section.className = "publish-summary";
    section.append(...rows);
    elements.publishSummary.append(section);
  }

  function renderSources() {
    elements.sourceList.replaceChildren();
    if (state.sources.length === 0) {
      elements.sourceList.append(empty("Add a USK social source to import an outbox."));
      return;
    }
    for (const source of state.sources) {
      const item = document.createElement("article");
      item.className = "source-item";
      item.append(
        headingText(source.label, "h3"),
        paragraph("source-uri", source.uriSummary),
        summaryRow("Status", source.lastStatus || "Not fetched"),
        summaryRow("Last check", source.lastCheckedAt || ""),
        summaryRow("Last seen edition", source.lastSeenEdition || ""),
        summaryRow("Resolved URI", source.lastSeenResolvedUriSummary || ""),
        summaryRow("Source URI SHA-256", source.uriHash || ""),
        summaryRow("Updates", String(source.updateCount || 0)),
        summaryRow("Backoff or error", source.lastError || "")
      );
      const actions = document.createElement("div");
      actions.className = "source-actions";
      actions.append(actionButton("Fetch current", () => refreshSource(source.id)));
      item.append(actions);
      elements.sourceList.append(item);
    }
  }

  function renderSubscriptions() {
    elements.subscriptionList.replaceChildren();
    if (state.subscriptions.length === 0) {
      elements.subscriptionList.append(empty("No platform social source subscriptions are recorded."));
      return;
    }
    for (const subscription of state.subscriptions) {
      const id = subscriptionId(subscription);
      const item = document.createElement("article");
      item.className = "subscription-item";
      item.append(
        headingText(stringField(subscription, "label") || id, "h3"),
        summaryRow("Subscription", id),
        summaryRow("Status", stringField(subscription, "status", "state")),
        summaryRow("Last check", stringField(subscription, "lastCheckedAt", "lastCheckAt")),
        summaryRow("Last seen edition", stringField(subscription, "lastSeenEdition")),
        summaryRow("Resolved URI", stringField(subscription, "lastSeenResolvedUri")),
        summaryRow("Updates", String(numberField(subscription, "updateCount"))),
        summaryRow(
          "Backoff or error",
          stringField(subscription, "lastError", "lastErrorCode", "errorSummary")
        )
      );
      const actions = document.createElement("div");
      actions.className = "subscription-actions";
      actions.append(
        actionButton("Refresh", () => mutateSubscription(id, "refresh")),
        actionButton("Pause", () => mutateSubscription(id, "pause")),
        actionButton("Resume", () => mutateSubscription(id, "resume")),
        actionButton("Delete", () => mutateSubscription(id, "remove"))
      );
      item.append(actions);
      elements.subscriptionList.append(item);
    }
  }

  function renderInbox() {
    elements.inboxList.replaceChildren();
    const visibleMessages = state.importedMessages.filter((message) => !readState(message).archived);
    if (visibleMessages.length === 0) {
      elements.inboxList.append(empty("Imported message summaries appear here as plain text."));
      return;
    }
    for (const message of visibleMessages) {
      const itemState = readState(message);
      const card = document.createElement("article");
      card.className = "message-card";
      card.append(
        headingText(message.subject || "(no subject)", "h3"),
        paragraph(
          "message-meta",
          `${message.authorLabel || "Unknown author"} / ${message.authorFingerprint}`
        ),
        paragraph("message-meta", `${message.sourceLabel || "source"} / ${message.createdAt}`),
        paragraph("message-body", message.bodyPreview || ""),
        trustBadges(message),
        messageActionBar(message, itemState)
      );
      elements.inboxList.append(card);
    }
  }

  function renderQueue(response) {
    elements.queuePreview.replaceChildren();
    const rows = queueRows(response);
    if (rows.length === 0) {
      elements.queuePreview.append(empty("No upload queue rows are available."));
      return;
    }
    const content = document.createElement("div");
    content.className = "queue-content";
    for (const row of rows.slice(0, 8)) {
      const item = document.createElement("article");
      item.className = "queue-item";
      item.append(
        summaryRow("Identifier", row.identifier),
        summaryRow("Status", row.status),
        summaryRow("Progress", row.progress)
      );
      content.append(item);
    }
    elements.queuePreview.append(content);
  }

  function messageActionBar(message, itemState) {
    const actions = document.createElement("div");
    actions.className = "message-actions";
    actions.append(
      actionButton(itemState.read ? "Mark unread" : "Mark read", () =>
        updateMessageState(message.messageId, { read: !itemState.read, lastViewedAt: new Date().toISOString() })
      ),
      actionButton(itemState.pinned ? "Unpin" : "Pin", () =>
        updateMessageState(message.messageId, { pinned: !itemState.pinned })
      ),
      actionButton("Archive", () => updateMessageState(message.messageId, { archived: true }))
    );
    return actions;
  }

  async function updateMessageState(messageId, patch) {
    state.readState[messageId] = Object.assign({}, state.readState[messageId] || {}, patch);
    await persistReadState();
    renderInbox();
  }

  function trustBadges(message) {
    const score = state.trustScores[message.authorFingerprint];
    const values = [];
    const itemState = readState(message);
    values.push(itemState.read ? "read" : "unread");
    if (itemState.pinned) {
      values.push("pinned");
    }
    if (!score) {
      return badges(values.concat(["trust unscored"]));
    }
    if (score.status === "scored") {
      values.push(`trust ${score.value}`);
      values.push(`${score.evidenceCount} evidence`);
      return badges(values, "score");
    }
    values.push("trust neutral");
    return badges(values, "warning");
  }

  function normalizeTrustScore(score) {
    const value = numberField(score, "score", "value");
    const evidence = score && Array.isArray(score.evidence) ? score.evidence.length : 0;
    if (Number.isFinite(value)) {
      return { status: "scored", value, evidenceCount: evidence };
    }
    return { status: "unscored", summary: "No local trust evidence." };
  }

  function syncSourceSubscriptionMetadata() {
    const byId = new Map();
    for (const subscription of state.subscriptions) {
      byId.set(subscriptionId(subscription), subscription);
    }
    state.sources = state.sources.map((source) => {
      const subscription = byId.get(source.subscriptionId);
      if (!subscription) {
        return source;
      }
      return Object.assign({}, source, {
        lastCheckedAt: stringField(subscription, "lastCheckedAt", "lastCheckAt") || source.lastCheckedAt,
        lastSeenEdition: stringField(subscription, "lastSeenEdition") || source.lastSeenEdition,
        lastSeenResolvedUriSummary:
          redactedPublicUri(stringField(subscription, "lastSeenResolvedUri")) ||
          source.lastSeenResolvedUriSummary,
        updateCount: numberField(subscription, "updateCount") || source.updateCount || 0,
        lastError:
          stringField(subscription, "lastError", "lastErrorCode", "errorSummary") ||
          source.lastError,
      });
    });
  }

  function selectedIdentity() {
    return state.identities.find((identity) => identityId(identity) === state.selectedIdentityId);
  }

  function identityId(identity) {
    return stringField(identity, "identityId", "id");
  }

  function identityLabel(identity) {
    return stringField(identity, "label", "name") || identityId(identity) || "Identity";
  }

  function subscriptionId(subscription) {
    return stringField(subscription, "subscriptionId", "id");
  }

  function subscriptionForSource(source) {
    return state.subscriptions.find((subscription) => subscriptionId(subscription) === source.subscriptionId);
  }

  function sourceFetchUri(source) {
    const subscription = subscriptionForSource(source);
    return stringField(subscription, "lastSeenResolvedUri", "resolvedUri", "sourceUri", "uri");
  }

  function readState(message) {
    return state.readState[message.messageId] || {};
  }

  function messageDraftFromForm(formData) {
    return {
      channel: textValue(formData, "channel") || "general",
      subject: boundedPreview(textValue(formData, "subject"), 160),
      body: textValue(formData, "body"),
      authorLabel: fieldValue(elements.profileForm, "authorLabel"),
      profileUri: fieldValue(elements.profileForm, "profileUri"),
      replyTo: textValue(formData, "replyTo"),
      recipientFingerprint: textValue(formData, "recipientFingerprint"),
      tags: tagsFromText(textValue(formData, "tags")),
    };
  }

  async function localOutboxSummary() {
    const summaries = [];
    for (const signedMessage of state.localOutbox) {
      const message = signedMessage.message || {};
      const signature = signedMessage.signature || {};
      summaries.push({
        messageId: stringValue(message.messageId),
        authorFingerprint: stringValue(message.authorFingerprint),
        createdAt: stringValue(message.createdAt),
        channel: stringValue(message.channel),
        subject: boundedPreview(stringValue(message.subject), 160),
        bodySha256: await sha256Hex(stringValue(message.body)),
        signatureSha256: await sha256Hex(stringValue(signature.signatureBase64)),
      });
    }
    return {
      updatedAt: new Date().toISOString(),
      localMessageCount: state.localOutbox.length,
      messages: summaries,
    };
  }

  function boundedDraft(message) {
    return {
      channel: boundedPreview(message.channel, 64),
      subject: boundedPreview(message.subject, 160),
      body: boundedPreview(message.body, maxDraftBodyLength),
      replyTo: boundedPreview(message.replyTo, 512),
      recipientFingerprint: boundedPreview(message.recipientFingerprint, 128),
      tags: message.tags.slice(0, 12),
      savedAt: new Date().toISOString(),
    };
  }

  function boundedDrafts(drafts) {
    const value = drafts && typeof drafts === "object" && !Array.isArray(drafts) ? drafts : {};
    const result = {};
    if (value.profileUri) {
      result.profileUri = boundedPreview(stringValue(value.profileUri), 512);
    }
    if (value.authorLabel) {
      result.authorLabel = boundedPreview(stringValue(value.authorLabel), 80);
    }
    if (value.message && typeof value.message === "object" && !Array.isArray(value.message)) {
      result.message = boundedDraft(value.message);
    }
    return result;
  }

  function boundedSources(sources) {
    return boundedArray(sources, maxSources).map((source) => ({
      id: boundedPreview(source.id, 80),
      label: boundedPreview(source.label, 80) || "Social source",
      uriHash: boundedPreview(source.uriHash, 64),
      uriSummary: boundedPreview(source.uriSummary, 96) || "USK social source URI redacted",
      subscriptionId: boundedPreview(source.subscriptionId, 120),
      lastCheckedAt: boundedPreview(source.lastCheckedAt, 64),
      lastStatus: boundedPreview(source.lastStatus, 80),
      lastSeenEdition: boundedPreview(source.lastSeenEdition, 40),
      lastSeenResolvedUriSummary: boundedPreview(source.lastSeenResolvedUriSummary, 96),
      updateCount: Math.max(0, numberField(source, "updateCount")),
      lastError: boundedPreview(source.lastError, 160),
    }));
  }

  function boundedArray(value, limit) {
    return Array.isArray(value) ? value.slice(0, limit) : [];
  }

  function boundedObject(value, limit) {
    const source = value && typeof value === "object" && !Array.isArray(value) ? value : {};
    const result = {};
    for (const key of Object.keys(source).slice(0, limit)) {
      result[key] = source[key];
    }
    return result;
  }

  function tagsFromText(value) {
    return stringValue(value)
      .split(",")
      .map((tag) => tag.trim())
      .filter((tag) => tag)
      .slice(0, 12);
  }

  function queueRows(response) {
    const candidates = [];
    if (Array.isArray(response)) {
      candidates.push(...response);
    }
    if (response && typeof response === "object") {
      for (const key of ["requests", "items", "uploads", "queue"]) {
        if (Array.isArray(response[key])) {
          candidates.push(...response[key]);
        }
      }
    }
    return candidates.map((item) => ({
      identifier: stringField(item, "identifier", "id", "requestId") || "request",
      status: stringField(item, "status", "state") || "unknown",
      progress: stringField(item, "progress", "percentComplete") || "",
    }));
  }

  function fetchedTextFromResponse(response) {
    return stringField(response, "contentText", "text", "content", "body");
  }

  function parseJsonObject(value, description) {
    try {
      return parsePlainObject(JSON.parse(value), description);
    } catch (error) {
      throw new Error(`${description} must be a JSON object.`);
    }
  }

  function parsePlainObject(value, description) {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new Error(`${description} must be a JSON object.`);
    }
    return value;
  }

  function isSocialSourceUri(uri) {
    const value = stringValue(uri);
    return value.startsWith("USK@") || value.startsWith("crypta:USK@");
  }

  function redactedInsertUri(uri) {
    const value = stringValue(uri);
    if (value.startsWith("KSK@")) {
      return "KSK insert URI accepted and not stored";
    }
    return "private insert URI redacted and not stored";
  }

  function redactedPublicUri(uri) {
    const value = stringValue(uri);
    if (!value) {
      return "";
    }
    if (value.startsWith("USK@") || value.startsWith("crypta:USK@")) {
      return "USK social source URI redacted";
    }
    if (value.startsWith("CHK@") || value.startsWith("crypta:CHK@")) {
      return "CHK content URI redacted";
    }
    return "content URI redacted";
  }

  function summaryRow(label, value) {
    const row = document.createElement("p");
    row.className = "summary-row";
    const strong = document.createElement("strong");
    strong.textContent = `${label}: `;
    const span = document.createElement("span");
    span.textContent = stringValue(value) || "not available";
    row.append(strong, span);
    return row;
  }

  function headingText(value, level) {
    const heading = document.createElement(level);
    heading.textContent = stringValue(value) || "Untitled";
    return heading;
  }

  function paragraph(className, value) {
    const node = document.createElement("p");
    node.className = className;
    node.textContent = stringValue(value);
    return node;
  }

  function badges(values, mode) {
    const container = document.createElement("div");
    container.className = "message-badges";
    for (const value of values.filter((item) => stringValue(item))) {
      const badge = document.createElement("span");
      badge.className = `badge badge--${mode || "neutral"}`;
      badge.textContent = stringValue(value);
      container.append(badge);
    }
    return container;
  }

  function actionButton(label, handler) {
    const button = document.createElement("button");
    button.className = "cr-button cr-button--secondary";
    button.type = "button";
    button.textContent = label;
    button.addEventListener("click", handler);
    return button;
  }

  function empty(text) {
    const node = document.createElement("p");
    node.className = "cr-empty";
    node.textContent = text;
    return node;
  }

  function fieldValue(form, name) {
    const field = form.elements.namedItem(name);
    return field && "value" in field ? stringValue(field.value).trim() : "";
  }

  function setFieldValue(form, name, value) {
    const field = form.elements.namedItem(name);
    if (field && "value" in field) {
      field.value = value;
    }
  }

  function textValue(formData, name) {
    const value = formData.get(name);
    return typeof value === "string" ? value.trim() : "";
  }

  function checkboxValue(form, name) {
    const field = form.elements.namedItem(name);
    return field instanceof HTMLInputElement && field.checked;
  }

  function stringValue(value) {
    return typeof value === "string" ? value.trim() : "";
  }

  function rawString(value) {
    return typeof value === "string" ? value : "";
  }

  function stringField(object, ...names) {
    if (!object || typeof object !== "object") {
      return "";
    }
    for (const name of names) {
      const value = object[name];
      if (typeof value === "string" && value.trim()) {
        return value.trim();
      }
    }
    return "";
  }

  function numberField(object, ...names) {
    if (!object || typeof object !== "object") {
      return 0;
    }
    for (const name of names) {
      const value = object[name];
      if (typeof value === "number" && Number.isFinite(value)) {
        return value;
      }
      if (typeof value === "string" && /^-?[0-9]+$/.test(value.trim())) {
        return Number.parseInt(value.trim(), 10);
      }
    }
    return 0;
  }

  function boundedPreview(value, maxLength) {
    const text = stringValue(value);
    if (text.length <= maxLength) {
      return text;
    }
    return text.slice(0, Math.max(0, maxLength - 3)) + "...";
  }

  function generatedId(prefix) {
    return `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
  }

  async function sha256Hex(value) {
    let data;
    if (value instanceof Uint8Array) {
      data = value;
    } else if (value instanceof ArrayBuffer) {
      data = new Uint8Array(value);
    } else {
      data = new TextEncoder().encode(typeof value === "string" ? value : String(value || ""));
    }
    const digest = await window.crypto.subtle.digest("SHA-256", data);
    return Array.from(new Uint8Array(digest))
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join("");
  }

  function setStatus(message, tone) {
    elements.status.textContent = message || "";
    elements.status.dataset.tone = tone || "default";
  }
})();
