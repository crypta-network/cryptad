(function () {
  "use strict";

  const appId = "social-inbox";
  const socialMessageType = "crypta.social.message.v1";
  const socialOutboxType = "crypta.social.outbox.v1";
  const socialOutboxContentType = "application/vnd.crypta.social.outbox+json";
  const socialOutboxTargetFilename = "social-outbox.json";
  const trustScoreProviderAppId = "trust-graph";
  const trustScoreServiceId = "trust.score";
  const trustScoreScope = "score.read";
  const trustScoreContext = "message-author";
  const maxSources = 16;
  const maxImportedMessages = 160;
  const maxLocalOutboxMessages = 24;
  const maxReadStateEntries = 240;
  const maxRenderedThreads = 80;
  const maxRenderedThreadMessages = 140;
  const maxThreadDepth = 12;
  const maxSearchQueryLength = 80;
  const maxDraftBodyLength = 4096;
  const maxImportedSubjectLength = 160;
  const maxImportedChannelLength = 64;
  const maxMessageReferenceLength = 512;
  const maxRecipientFingerprintLength = 128;
  const maxAuthorLabelLength = 80;
  const maxProfileUriLength = 512;
  const maxDisplayTextLength = 240;
  const maxSourceLabelLength = 80;
  const maxSourceSummaryLength = 96;
  const maxTagCount = 12;
  const maxTagLength = 32;
  const maxImportedBodyPreviewLength = 700;
  const maxSourcesPerMessage = 8;
  const maxFetchedDocumentChars = 128 * 1024;
  const sourcePollIntervalSeconds = 15 * 60;
  const subscriptionStatusLabels = Object.freeze({
    queue_pressure: "Queue pressure",
    runtime_unavailable: "Runtime unavailable",
    backoff: "Backoff",
    budget_exhausted: "Budget exhausted",
    scheduled: "Scheduled",
    running: "Polling",
    success: "Active",
    paused: "Paused",
    disabled: "Disabled",
  });
  const dataSchemaVersion = 1;
  const messageIdPattern = /^msg-[0-9a-f]{64}$/;

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
    readState: Object.create(null),
    drafts: {},
    outboxSummary: null,
    trustScores: {},
    trustServiceDescriptor: null,
    trustServiceGrants: [],
    trustServiceBundles: [],
    trustServiceError: "",
    channelFilter: "",
    readFilter: "active",
    searchQuery: "",
  };

  const elements = {
    composeForm: document.getElementById("compose-form"),
    identityForm: document.getElementById("identity-form"),
    identitySelect: document.getElementById("identity-select"),
    identitySummary: document.getElementById("identity-summary"),
    channelFilter: document.getElementById("channel-filter"),
    inboxFilters: document.getElementById("inbox-filters"),
    inboxList: document.getElementById("inbox-list"),
    inboxResultSummary: document.getElementById("inbox-result-summary"),
    outboxList: document.getElementById("outbox-list"),
    prepareProfileButton: document.getElementById("prepare-profile-button"),
    profileForm: document.getElementById("profile-form"),
    profilePreview: document.getElementById("profile-preview"),
    publishForm: document.getElementById("publish-form"),
    publishSummary: document.getElementById("publish-summary"),
    queuePreview: document.getElementById("queue-preview"),
    refreshIdentitiesButton: document.getElementById("refresh-identities-button"),
    refreshAllSourcesButton: document.getElementById("refresh-all-sources-button"),
    refreshQueueButton: document.getElementById("refresh-queue-button"),
    refreshSubscriptionsButton: document.getElementById("refresh-subscriptions-button"),
    refreshTrustButton: document.getElementById("refresh-trust-button"),
    requestTrustGrantButton: document.getElementById("request-trust-grant-button"),
    replyContext: document.getElementById("reply-context"),
    clearReplyButton: document.getElementById("clear-reply-button"),
    readFilter: document.getElementById("read-filter"),
    searchInput: document.getElementById("search-input"),
    clearSearchButton: document.getElementById("clear-search-button"),
    sourceForm: document.getElementById("source-form"),
    sourceList: document.getElementById("source-list"),
    status: document.getElementById("status"),
    subscriptionList: document.getElementById("subscription-list"),
    trustServiceStatus: document.getElementById("trust-service-status"),
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
      await refreshTrustServiceStatus({ silent: true });
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
    elements.refreshAllSourcesButton.addEventListener("click", refreshAllSources);
    elements.refreshQueueButton.addEventListener("click", refreshUploadQueue);
    elements.refreshSubscriptionsButton.addEventListener("click", refreshSubscriptions);
    elements.refreshTrustButton.addEventListener("click", refreshTrustAnnotations);
    elements.requestTrustGrantButton.addEventListener("click", requestTrustServiceGrant);
    elements.inboxFilters.addEventListener("submit", (event) => event.preventDefault());
    elements.channelFilter.addEventListener("change", updateChannelFilter);
    elements.readFilter.addEventListener("change", updateReadFilter);
    elements.searchInput.addEventListener("input", updateSearchQuery);
    elements.clearSearchButton.addEventListener("click", clearSearchQuery);
    elements.clearReplyButton.addEventListener("click", clearReplyContext);
    elements.composeForm.elements.namedItem("replyTo").addEventListener("input", renderReplyContext);
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
    const profileUri = optionalCryptaContentUri(textValue(formData, "profileUri"));
    if (textValue(formData, "profileUri") && !profileUri) {
      setStatus("Profile URI must be a Crypta content key.", "error");
      return;
    }
    const displayName =
      boundedPreview(textValue(formData, "displayName") || textValue(formData, "authorLabel"), 160);
    if (!displayName) {
      setStatus("Profile document display name is required.", "error");
      return;
    }
    try {
      const profileDocument = await CryptaPlatform.vault.identities.createProfileDocument(
        identityId(identity),
        {
          displayName,
          website: profileUri,
          contactUri: profileUri,
          tags: ["social-inbox", "rc"],
        }
      );
      elements.profilePreview.textContent = boundedPreview(
        JSON.stringify(profileDocument, null, 2),
        maxFetchedDocumentChars,
      );
      state.drafts.profileUri = profileUri;
      state.drafts.authorLabel = boundedPreview(textValue(formData, "authorLabel"), maxAuthorLabelLength);
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
    if (fieldValue(elements.profileForm, "profileUri") && !message.profileUri) {
      setStatus("Profile URI must be a Crypta content key.", "error");
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
      renderAll();
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
    const rawPublicSourceUri = textValue(formData, "publicSourceUri");
    const publicSourceUri = optionalCryptaContentUri(rawPublicSourceUri, ["USK"]);
    if (rawPublicSourceUri && !publicSourceUri) {
      setStatus("Public source URI summary must be a USK@ or crypta:USK@ content key.", "error");
      return;
    }
    const sourceLabel =
      boundedPreview(textValue(formData, "sourceLabel"), maxSourceLabelLength) ||
      "Social Inbox RC";
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
    const uri = normalizedCryptaContentUri(textValue(formData, "uri"), ["USK"]);
    if (!uri) {
      setStatus("Social sources must start with USK@ or crypta:USK@.", "error");
      return;
    }
    const uriHash = await sha256Hex(uri);
    const source = {
      id: generatedId("source"),
      label: boundedPreview(textValue(formData, "label"), maxSourceLabelLength) || "Social source",
      uriHash,
      uriSummary: redactedPublicUri(uri),
      subscriptionId: "",
      lastCheckedAt: "",
      lastStatus: "Not fetched",
      lastSubscriptionStatus: "",
      lastSubscriptionRetry: "",
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
        throw new Error("Refresh subscriptions before fetching this source, and use a valid USK URI.");
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

  async function refreshAllActiveSources() {
    const activeSourceIds = state.sources
      .filter((source) => source.subscriptionId && source.lastStatus !== "Subscription removed")
      .map((source) => source.id)
      .slice(0, maxSources);
    if (activeSourceIds.length === 0) {
      setStatus("No active social sources are available to refresh.", "warning");
      return;
    }
    setStatus(`Refreshing ${activeSourceIds.length} active social source subscriptions...`);
    for (const sourceId of activeSourceIds) {
      const source = state.sources.find((item) => item.id === sourceId);
      if (!source || !source.subscriptionId) {
        continue;
      }
      try {
        await CryptaPlatform.content.subscriptions.refresh(source.subscriptionId);
        source.lastCheckedAt = new Date().toISOString();
        source.lastStatus = "Refresh requested";
        source.lastError = "";
      } catch (error) {
        source.lastStatus = "Error";
        source.lastError = CryptaPlatform.api.errorMessage(error);
      }
    }
    await persistSources();
    await refreshSubscriptions({ silent: true });
    renderAll();
    setStatus("Active social source subscription refresh requested.");
  }

  async function refreshAllSources() {
    await refreshAllActiveSources();
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
    const messageId = rawString(message.messageId);
    return {
      messageId,
      authorFingerprint: boundedPreview(message.authorFingerprint, maxRecipientFingerprintLength),
      authorLabel: boundedPreview(message.authorLabel, maxAuthorLabelLength),
      profileUri: optionalCryptaContentUri(message.profileUri),
      channel: normalizeChannel(message.channel),
      subject: boundedPreview(stringValue(message.subject), maxImportedSubjectLength),
      bodyPreview: boundedPreview(body, maxImportedBodyPreviewLength),
      bodySha256: await sha256Hex(body),
      createdAt: boundedPreview(message.createdAt, 64),
      replyTo: normalizeReplyReference(message.replyTo),
      tags: boundedTags(message.tags),
      sourceId: source.id,
      sourceLabel: boundedPreview(source.label, maxSourceLabelLength),
      sourceUriHash: source.uriHash || (await sha256Hex(source.subscriptionId || source.id)),
      resolvedUri: redactedPublicUri(stringField(response, "resolvedUri", "requestedUri")),
      signatureSha256: await sha256Hex(stringValue(signature.signatureBase64)),
      importedAt: new Date().toISOString(),
      firstImportedAt: new Date().toISOString(),
      lastSeenAt: new Date().toISOString(),
      seenCount: 1,
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
    if (!isSafeMessageId(rawString(message.messageId))) {
      throw new Error("Social message id is malformed.");
    }
    requireBoundedText(message.channel, maxImportedChannelLength, "channel");
    requireBoundedText(message.subject, maxImportedSubjectLength, "subject");
    requireBoundedText(message.authorLabel, maxAuthorLabelLength, "authorLabel");
    requireBoundedText(message.profileUri, maxProfileUriLength, "profileUri");
    if (rawString(message.profileUri) && !optionalCryptaContentUri(message.profileUri)) {
      throw new Error("Social message profile URI is malformed.");
    }
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
    const expectedMessageId = await expectedSocialMessageId(message);
    if (rawString(message.messageId) !== expectedMessageId) {
      throw new Error("Social message id does not match canonical payload.");
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

  async function expectedSocialMessageId(message) {
    return `msg-${await sha256Hex(canonicalSocialMessageIdPayload(message))}`;
  }

  function canonicalSocialMessageIdPayload(message) {
    const payload = {
      appId: rawString(message.appId),
      identityId: rawString(message.identityId),
      authorFingerprint: rawString(message.authorFingerprint),
    };
    appendOptionalCanonicalField(payload, "authorLabel", message.authorLabel);
    appendOptionalCanonicalField(payload, "profileUri", message.profileUri);
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
    return JSON.stringify(payload);
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
      byId.set(existing.messageId, boundedImportedMessage(existing));
    }
    for (const message of messages) {
      const existing = byId.get(message.messageId);
      byId.set(message.messageId, mergeImportedMessageSummary(existing, message));
    }
    state.importedMessages = Array.from(byId.values())
      .sort((left, right) => stringValue(right.createdAt).localeCompare(stringValue(left.createdAt)))
      .slice(0, maxImportedMessages);
  }

  function mergeImportedMessageSummary(existing, incoming) {
    const current = existing || incoming;
    const firstImportedAt = earliestTimestamp(
      current.firstImportedAt || current.importedAt,
      incoming.firstImportedAt || incoming.importedAt
    );
    const lastSeenAt = latestTimestamp(
      current.lastSeenAt || current.importedAt,
      incoming.lastSeenAt || incoming.importedAt
    );
    const sourcesSeen = mergeSourceSummaries(
      sourceSummariesForDedupe(current),
      sourceSummariesForDedupe(incoming)
    );
    return boundedImportedMessage(
      Object.assign({}, current, {
        firstImportedAt,
        lastSeenAt,
        seenCount: existing
          ? Math.min(9999, Math.max(1, numberField(current, "seenCount")) + 1)
          : Math.max(1, numberField(incoming, "seenCount")),
        sourcesSeen,
        sourceId: current.sourceId || incoming.sourceId,
        sourceLabel: current.sourceLabel || incoming.sourceLabel,
        sourceUriHash: current.sourceUriHash || incoming.sourceUriHash,
        importedAt: firstImportedAt,
      })
    );
  }

  function sourceSummariesForDedupe(message) {
    const summaries = boundedSourceSummaries(message && message.sourcesSeen);
    if (summaries.length > 0) {
      return summaries;
    }
    const fallback = sourceSummaryFromMessage(message);
    const fallbackKey = fallback.sourceUriHash || fallback.sourceId || fallback.sourceLabel;
    return fallbackKey ? [fallback] : [];
  }

  function sourceSummaryFromMessage(message) {
    return {
      sourceId: boundedPreview(message && message.sourceId, 80),
      sourceLabel: boundedPreview(message && message.sourceLabel, maxSourceLabelLength),
      sourceUriHash: boundedPreview(message && message.sourceUriHash, 64),
      importedAt: boundedPreview(message && (message.lastSeenAt || message.importedAt), 64),
    };
  }

  function mergeSourceSummaries(left, right) {
    const byKey = new Map();
    for (const summary of boundedArray(left, maxSourcesPerMessage).concat(
      boundedArray(right, maxSourcesPerMessage)
    )) {
      const bounded = boundedSourceSummary(summary);
      const key = bounded.sourceUriHash || bounded.sourceId || bounded.sourceLabel;
      if (!key) {
        continue;
      }
      const existing = byKey.get(key);
      byKey.set(
        key,
        existing
          ? Object.assign({}, existing, {
              importedAt: latestTimestamp(existing.importedAt, bounded.importedAt),
            })
          : bounded
      );
    }
    return Array.from(byKey.values()).slice(0, maxSourcesPerMessage);
  }

  function boundedSourceSummary(summary) {
    return {
      sourceId: boundedPreview(summary && summary.sourceId, 80),
      sourceLabel:
        boundedPreview(summary && summary.sourceLabel, maxSourceLabelLength) || "Social source",
      sourceUriHash: boundedPreview(summary && summary.sourceUriHash, 64),
      importedAt: boundedPreview(summary && summary.importedAt, 64),
    };
  }

  async function refreshTrustAnnotations(options) {
    const fingerprints = uniqueFingerprints();
    if (fingerprints.length === 0) {
      if (!(options && options.silent)) {
        setStatus("No message authors to score.");
      }
      return;
    }
    if (!activeTrustServiceGrant()) {
      await refreshTrustServiceStatus({ silent: true });
    }
    const grant = activeTrustServiceGrant();
    if (!grant) {
      markTrustScoresUnavailable(fingerprints, trustServiceUnavailableSummary());
      renderInbox();
      if (!(options && options.silent)) {
        setStatus(trustServiceUnavailableSummary(), "warning");
      }
      return;
    }
    for (const fingerprint of fingerprints) {
      try {
        const response = await CryptaPlatform.services.invoke(trustScoreProviderAppId, trustScoreServiceId, {
          subjectKind: "identity",
          subjectUri: fingerprint,
          context: trustScoreContext,
          scope: trustScoreScope,
        });
        const result =
          response && response.serviceCall && response.serviceCall.result
            ? response.serviceCall.result
            : response;
        state.trustScores[fingerprint] = normalizeTrustScore(result);
      } catch (error) {
        state.trustScores[fingerprint] = {
          status: "unscored",
          summary: "Trust score unavailable / grant required.",
        };
        await refreshTrustServiceStatus({ silent: true });
      }
    }
    renderInbox();
    if (!(options && options.silent)) {
      setStatus("Trust annotations refreshed.");
    }
  }

  async function refreshTrustServiceStatus(options) {
    try {
      const serviceResponse = await CryptaPlatform.services.get(
        trustScoreProviderAppId,
        trustScoreServiceId
      );
      const grantsResponse = await CryptaPlatform.services.grants.list();
      const bundlesResponse = await CryptaPlatform.services.bundles.list();
      state.trustServiceDescriptor = serviceResponse.service || serviceResponse;
      state.trustServiceGrants = boundedArray(grantsResponse.grants || grantsResponse, 20);
      state.trustServiceBundles = boundedArray(bundlesResponse.bundles || bundlesResponse, 20);
      state.trustServiceError = "";
      renderTrustServiceStatus();
      if (!(options && options.silent)) {
        setStatus("Trust Score Service status refreshed.");
      }
    } catch (error) {
      state.trustServiceDescriptor = null;
      state.trustServiceGrants = [];
      state.trustServiceBundles = [];
      state.trustServiceError = CryptaPlatform.api.errorMessage(error);
      renderTrustServiceStatus();
      if (!(options && options.silent)) {
        setStatus(state.trustServiceError, "warning");
      }
    }
  }

  async function requestTrustServiceGrant() {
    try {
      setStatus("Requesting Trust Score Service grant bundle...");
      await CryptaPlatform.services.bundles.request({
        bundleAlias: "trust-annotations",
        includeOptional: true,
        purpose:
          "Annotate Social Inbox message authors using the local Trust Graph Local RC score service.",
      });
      await refreshTrustServiceStatus({ silent: true });
      setStatus("Trust Score Service grant bundle requested; an operator must approve it.");
    } catch (error) {
      setStatus(CryptaPlatform.api.errorMessage(error), "error");
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
    state.channelFilter = normalizeChannelFilter(uiState.channelFilter);
    state.readFilter = normalizeReadFilter(uiState.readFilter);
    state.sources = boundedArray(await readAppDataRecord(records.sources, []), maxSources);
    state.outboxSummary = await readAppDataRecord(records.outboxSummary, null);
    state.importedMessages = boundedImportedMessages(
      await readAppDataRecord(records.importedMessageIndex, []),
      maxImportedMessages
    );
    state.readState = boundedReadState(
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
      channelFilter: state.channelFilter,
      readFilter: state.readFilter,
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
    state.importedMessages = boundedImportedMessages(state.importedMessages, maxImportedMessages);
    await putJsonRecord(records.importedMessageIndex, state.importedMessages);
  }

  async function persistReadState() {
    state.readState = boundedReadState(state.readState, maxReadStateEntries);
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
    renderTrustServiceStatus();
    renderInboxControls();
    renderReplyContext();
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
      const subscription = subscriptionForSource(source);
      const item = document.createElement("article");
      item.className = "source-item";
      item.append(
        headingText(source.label, "h3"),
        sourceStatusBadges(source),
        paragraph("source-uri", source.uriSummary),
        summaryRow("Status", source.lastStatus || "Not fetched"),
        summaryRow(
          "Subscription state",
          subscriptionStatusSummary(subscription) || source.lastSubscriptionStatus
        ),
        summaryRow("Last check", source.lastCheckedAt || ""),
        summaryRow("Last seen edition", source.lastSeenEdition || ""),
        summaryRow("Resolved URI", source.lastSeenResolvedUriSummary || ""),
        summaryRow("Source URI SHA-256", source.uriHash || ""),
        summaryRow("Updates", String(source.updateCount || 0)),
        summaryRow(
          "Retry window",
          subscriptionRetrySummary(subscription) || source.lastSubscriptionRetry
        ),
        summaryRow("Backoff or error", source.lastError || "")
      );
      const actions = document.createElement("div");
      actions.className = "source-actions";
      actions.append(actionButton("Fetch current", () => refreshSource(source.id)));
      item.append(actions);
      elements.sourceList.append(item);
    }
  }

  function sourceStatusBadges(source) {
    const values = [];
    const subscription = subscriptionForSource(source);
    const attentionStatus = subscriptionAttentionStatusSummary(subscription);
    if (source.lastError || source.lastStatus === "Error") {
      values.push("Error");
    }
    if (attentionStatus) {
      values.push(attentionStatus);
    }
    if (isSourceStale(source)) {
      values.push("Stale");
    }
    if (source.subscriptionId) {
      values.push("Subscribed");
    }
    return badges(
      values.length > 0 ? values : ["Not checked"],
      values.includes("Error") || attentionStatus ? "warning" : "neutral",
    );
  }

  function isSourceStale(source) {
    const lastChecked = timestampMillis(source.lastCheckedAt);
    if (!lastChecked) {
      return true;
    }
    return Date.now() - lastChecked > sourcePollIntervalSeconds * 2000;
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
        summaryRow("Status", subscriptionStatusSummary(subscription)),
        summaryRow("Last check", stringField(subscription, "lastCheckedAt", "lastCheckAt")),
        summaryRow("Last seen edition", stringField(subscription, "lastSeenEdition")),
        summaryRow("Resolved URI", redactedPublicUri(stringField(subscription, "lastSeenResolvedUri"))),
        summaryRow("Updates", String(numberField(subscription, "updateCount"))),
        summaryRow("Retry window", subscriptionRetrySummary(subscription)),
        summaryRow(
          "Backoff or error",
          subscriptionErrorSummary(subscription)
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

  function renderInboxControls() {
    const channels = discoveredChannels();
    elements.channelFilter.replaceChildren();
    const allOption = document.createElement("option");
    allOption.value = "";
    allOption.textContent = "All channels";
    elements.channelFilter.append(allOption);
    for (const channel of channels) {
      const option = document.createElement("option");
      option.value = channel;
      option.textContent = channel;
      elements.channelFilter.append(option);
    }
    if (state.channelFilter && !channels.includes(state.channelFilter)) {
      const option = document.createElement("option");
      option.value = state.channelFilter;
      option.textContent = state.channelFilter;
      elements.channelFilter.append(option);
    }
    elements.channelFilter.value = state.channelFilter;
    elements.readFilter.value = state.readFilter;
    elements.searchInput.value = state.searchQuery;
  }

  function renderInbox() {
    elements.inboxList.replaceChildren();
    const threadIndex = buildThreadIndex(allMessageSummaries(), state.readState);
    const visibleThreads = filterThreads(threadIndex.threads).slice(0, maxRenderedThreads);
    renderInboxResultSummary(threadIndex.threads.length, visibleThreads.length);
    if (visibleThreads.length === 0) {
      elements.inboxList.append(empty("Threaded message summaries appear here as plain text."));
      return;
    }
    for (const thread of visibleThreads) {
      elements.inboxList.append(renderThreadCard(thread));
    }
  }

  function renderInboxResultSummary(totalThreadCount, visibleThreadCount) {
    const query = normalizedSearchQuery();
    const fragments = [
      `${visibleThreadCount} of ${totalThreadCount} threads`,
      state.channelFilter ? `channel ${state.channelFilter}` : "all channels",
      state.readFilter,
    ];
    if (query) {
      fragments.push(`search ${query.length} chars`);
    }
    elements.inboxResultSummary.textContent = fragments.join(" / ");
  }

  function renderThreadCard(thread) {
    const card = document.createElement("article");
    card.className = "thread-card";
    card.append(
      renderThreadSummary(thread),
      threadActionBar(thread),
      renderThreadMessages(thread)
    );
    return card;
  }

  function renderThreadSummary(thread) {
    const section = document.createElement("section");
    section.className = "thread-summary";
    const title = headingText(thread.rootMessage.subject || "(no subject)", "h3");
    const meta = paragraph(
      "message-meta",
      `${thread.totalMessages} messages / ${thread.unreadMessages} unread / ${thread.sourceCount} sources`
    );
    section.append(
      title,
      meta,
      badges(
        [
          thread.pinned ? "pinned thread" : "",
          thread.archived ? "archived thread" : "",
          `channel ${thread.channel}`,
          `latest ${thread.latestAt || "not available"}`,
        ],
        thread.unreadMessages > 0 ? "warning" : "neutral"
      )
    );
    return section;
  }

  function renderThreadMessages(thread) {
    const container = document.createElement("div");
    container.className = "thread-messages";
    const rendered = new Set();
    let count = 0;
    const appendMessage = (message, depth) => {
      if (!message || rendered.has(message.messageId) || count >= maxRenderedThreadMessages) {
        return;
      }
      rendered.add(message.messageId);
      count += 1;
      container.append(renderMessageCard(message, thread, Math.min(depth, maxThreadDepth)));
      if (depth >= maxThreadDepth) {
        return;
      }
      const children = thread.children.get(message.messageId) || [];
      for (const child of children) {
        appendMessage(child, depth + 1);
      }
    };
    appendMessage(thread.rootMessage, 0);
    for (const message of thread.messages) {
      appendMessage(message, 1);
    }
    if (thread.messages.length > count) {
      container.append(empty("Additional thread messages are hidden by the local render cap."));
    }
    return container;
  }

  function renderMessageCard(message, thread, depth) {
      const card = document.createElement("article");
      card.className = "message-card";
    card.dataset.depth = String(depth);
      card.append(
        headingText(message.subject || "(no subject)", "h3"),
      renderAuthorBlock(message),
      paragraph("message-meta", messageMetaSummary(message)),
        paragraph("message-body", message.bodyPreview || ""),
        trustBadges(message),
      messageActionBar(message, readState(message), thread)
      );
    return card;
  }

  function renderAuthorBlock(message) {
    const section = document.createElement("section");
    section.className = "author-block";
    section.append(
      paragraph(
        "message-meta",
        `${message.authorLabel || "Unknown author"} / ${fingerprintSummary(message.authorFingerprint)}`
      )
    );
    if (message.profileUri) {
      section.append(summaryRow("Profile URI", message.profileUri));
      section.append(actionButton("Copy profile URI", () => copyProfileUri(message.profileUri)));
    }
    return section;
  }

  function messageMetaSummary(message) {
    const sourceCount = sourceCountForMessage(message);
    const source =
      sourceCount > 1
        ? `${sourceCount} sources`
        : boundedPreview(message.sourceLabel, maxSourceLabelLength) || "source";
    const replyTo = normalizeReplyReference(message.replyTo);
    return [
      `${source} / ${message.createdAt || "not available"}`,
      `Message ${message.messageId}`,
      replyTo ? `Reply to ${replyTo}` : "",
    ]
      .filter((value) => value)
      .join(" / ");
  }

  function threadActionBar(thread) {
    const actions = document.createElement("div");
    actions.className = "message-actions thread-actions";
    const allRead = thread.unreadMessages === 0;
    actions.append(
      actionButton(allRead ? "Mark thread unread" : "Mark thread read", () =>
        allRead ? markThreadUnread(thread) : markThreadRead(thread)
      ),
      actionButton(thread.pinned ? "Unpin thread" : "Pin thread", () => toggleThreadPin(thread)),
      actionButton(thread.archived ? "Unarchive thread" : "Archive thread", () => archiveThread(thread))
    );
    return actions;
  }

  function renderTrustServiceStatus() {
    elements.trustServiceStatus.replaceChildren();
    const descriptor = state.trustServiceDescriptor;
    const grant = preferredTrustServiceGrant();
    const pendingBundle = pendingTrustServiceBundle();
    const status = grant ? stringField(grant, "status") : "";
    const bundleStatus = pendingBundle ? stringField(pendingBundle, "status") : "";
    const serviceName = descriptor
      ? stringField(descriptor, "name") || trustScoreServiceId
      : "Trust Score Service";
    const rows = [
      summaryRow("Service", serviceName),
      summaryRow("Provider", descriptor ? stringField(descriptor, "providerName") : trustScoreProviderAppId),
      summaryRow("Service id", trustScoreServiceId),
      summaryRow("Scope", trustScoreScope),
      summaryRow("Context", trustScoreContext),
      summaryRow("Grant", status || trustServiceUnavailableSummary()),
    ];
    if (grant) {
      rows.push(summaryRow("Use count", String(numberField(grant, "useCount"))));
      rows.push(summaryRow("Last used", stringField(grant, "lastUsedAt")));
    }
    if (pendingBundle) {
      rows.push(summaryRow("Bundle", bundleStatus || "pending"));
    }
    if (state.trustServiceError) {
      rows.push(summaryRow("Status", state.trustServiceError));
    }
    elements.trustServiceStatus.append(...rows);
    elements.requestTrustGrantButton.disabled =
      !descriptor || ["active", "pending"].includes(status) || bundleStatus === "pending";
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

  function messageActionBar(message, itemState, thread) {
    const actions = document.createElement("div");
    actions.className = "message-actions";
    actions.append(
      actionButton("Reply", () => prepareReply(message)),
      actionButton(isMessageRead(message) ? "Mark unread" : "Mark read", () =>
        updateMessageState(message.messageId, {
          read: !isMessageRead(message),
          lastViewedAt: new Date().toISOString(),
        })
      ),
      actionButton(itemState.pinned ? "Unpin" : "Pin", () =>
        updateMessageState(message.messageId, { pinned: !itemState.pinned })
      ),
      actionButton(
        itemState.archived ? "Unarchive" : "Archive",
        () => updateMessageState(message.messageId, { archived: !itemState.archived })
      )
    );
    return actions;
  }

  async function markThreadRead(thread) {
    await updateThreadState(thread, {
      read: true,
      lastViewedAt: new Date().toISOString(),
    });
  }

  async function markThreadUnread(thread) {
    await updateThreadState(thread, {
      read: false,
      lastViewedAt: new Date().toISOString(),
    });
  }

  async function archiveThread(thread) {
    await updateThreadState(thread, { archived: !thread.archived });
  }

  async function toggleThreadPin(thread) {
    if (thread.pinned) {
      await updateThreadState(thread, { pinned: false });
      return;
    }
    await updateMessageState(thread.rootId, { pinned: true });
  }

  async function updateThreadState(thread, patch) {
    for (const message of thread.messages) {
      if (!isSafeMessageId(message.messageId)) {
        continue;
      }
      state.readState[message.messageId] = Object.assign(
        Object.create(null),
        state.readState[message.messageId] || {},
        patch
      );
    }
    await persistReadState();
    renderInbox();
  }

  async function updateMessageState(messageId, patch) {
    if (!isSafeMessageId(messageId)) {
      throw new Error("Cannot update read state for an unsafe message id.");
    }
    state.readState[messageId] = Object.assign(
      Object.create(null),
      state.readState[messageId] || {},
      patch
    );
    await persistReadState();
    renderInbox();
  }

  function trustBadges(message) {
    const score = state.trustScores[message.authorFingerprint];
    const values = [];
    const itemState = readState(message);
    values.push(isMessageRead(message) ? "read" : "unread");
    values.push(`channel ${normalizeChannel(message.channel)}`);
    if (itemState.pinned) {
      values.push("pinned");
    }
    if (itemState.archived) {
      values.push("archived");
    }
    if (message.local) {
      values.push("local outbox");
    }
    if (!score) {
      return badges(values.concat([trustServiceUnavailableSummary()]));
    }
    if (score.status === "scored") {
      values.push(`trust ${score.value}`);
      values.push(`${score.evidenceCount} evidence`);
      if (score.reasonSummary) {
        values.push(score.reasonSummary);
      }
      if (score.scopeSummary) {
        values.push(score.scopeSummary);
      }
      return badges(values, "score");
    }
    values.push(score.summary || "Trust score unavailable / grant required.");
    return badges(values, "warning");
  }

  function activeTrustServiceGrant() {
    return state.trustServiceGrants.find((grant) => trustGrantMatches(grant, "active"));
  }

  function preferredTrustServiceGrant() {
    return (
      activeTrustServiceGrant() ||
      state.trustServiceGrants.find((grant) => trustGrantMatches(grant, "pending")) ||
      state.trustServiceGrants.find((grant) => trustGrantMatches(grant, "expired")) ||
      state.trustServiceGrants.find((grant) =>
        trustGrantMatches(grant, "revalidation-required")
      ) ||
      state.trustServiceGrants.find((grant) => trustGrantMatches(grant, "inactive")) ||
      state.trustServiceGrants.find((grant) => trustGrantMatches(grant, "revoked")) ||
      null
    );
  }

  function pendingTrustServiceBundle() {
    return state.trustServiceBundles.find((bundle) => trustBundleMatches(bundle, "pending"));
  }

  function trustBundleMatches(bundle, status) {
    if (!bundle || stringField(bundle, "bundleAlias") !== "trust-annotations") {
      return false;
    }
    if (status && stringField(bundle, "status") !== status) {
      return false;
    }
    const dependencies = boundedArray(bundle.dependencies, 16);
    return dependencies.some(
      (dependency) =>
        stringField(dependency, "providerAppId") === trustScoreProviderAppId &&
        stringField(dependency, "serviceId") === trustScoreServiceId &&
        stringListField(dependency, "scopes", 16).includes(trustScoreScope) &&
        grantContextsCoverTrustScore(stringListField(dependency, "contexts", 16))
    );
  }

  function trustGrantMatches(grant, status) {
    return (
      grant &&
      stringField(grant, "providerAppId") === trustScoreProviderAppId &&
      stringField(grant, "serviceId") === trustScoreServiceId &&
      grantCoversTrustScore(grant) &&
      (!status || stringField(grant, "status") === status)
    );
  }

  function grantCoversTrustScore(grant) {
    const scopes = stringListField(grant, "scopes", 16);
    const contexts = stringListField(grant, "contexts", 16);
    return scopes.includes(trustScoreScope) && grantContextsCoverTrustScore(contexts);
  }

  function grantContextsCoverTrustScore(contexts) {
    if (contexts.includes(trustScoreContext)) {
      return true;
    }
    if (contexts.length > 0) {
      return false;
    }
    return stringListField(state.trustServiceDescriptor, "contexts", 16).length === 0;
  }

  function trustServiceUnavailableSummary() {
    const grant = preferredTrustServiceGrant();
    const status = grant ? stringField(grant, "status") : "";
    if (!state.trustServiceDescriptor) {
      return "Trust score unavailable / service not discovered.";
    }
    if (status === "pending") {
      return "Trust score unavailable / grant pending.";
    }
    if (pendingTrustServiceBundle()) {
      return "Trust score unavailable / grant bundle pending.";
    }
    if (status === "revoked") {
      return "Trust score unavailable / grant revoked.";
    }
    if (status === "expired") {
      return "Trust score unavailable / grant expired.";
    }
    if (status === "revalidation-required") {
      return "Trust score unavailable / grant requires operator revalidation.";
    }
    if (status === "inactive") {
      return "Trust score unavailable / grant inactive.";
    }
    return "Trust score unavailable / grant required.";
  }

  function markTrustScoresUnavailable(fingerprints, summary) {
    for (const fingerprint of fingerprints) {
      state.trustScores[fingerprint] = {
        status: "unscored",
        summary,
      };
    }
  }

  function normalizeTrustScore(score) {
    const trustStatus = stringField(score, "status");
    const value = optionalNumberField(score, "score", "value");
    const contributingEvidence = numberField(score, "contributingEvidenceCount", "contributingCount");
    const evidence =
      numberField(score, "evidenceCount") ||
      (score && Array.isArray(score.evidence) ? score.evidence.length : 0) ||
      contributingEvidence;
    if (
      ["trusted", "distrusted", "mixed"].includes(trustStatus) &&
      contributingEvidence > 0 &&
      Number.isFinite(value)
    ) {
      return {
        status: "scored",
        value,
        evidenceCount: evidence,
        reasonSummary: boundedTrustReasonSummary(score),
        scopeSummary: boundedPreview(stringField(score, "scope", "lifecycle", "scopeSummary"), 80),
      };
    }
    return { status: "unscored", summary: "No local trust evidence." };
  }

  function boundedTrustReasonSummary(score) {
    const reasons = stringListField(score, "reasonCodes", 4).concat(
      stringListField(score, "reasons", 4)
    );
    if (reasons.length === 0) {
      return "";
    }
    return `reasons ${reasons.map((reason) => boundedPreview(reason, 32)).slice(0, 4).join(", ")}`;
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
      const attentionStatus = subscriptionAttentionStatusSummary(subscription);
      return Object.assign({}, source, {
        lastCheckedAt: stringField(subscription, "lastCheckedAt", "lastCheckAt") || source.lastCheckedAt,
        lastStatus: sourceStatusAfterSubscriptionUpdate(source, attentionStatus),
        lastSubscriptionStatus:
          subscriptionStatusSummary(subscription) || source.lastSubscriptionStatus,
        lastSubscriptionRetry:
          subscriptionRetrySummary(subscription) || source.lastSubscriptionRetry,
        lastSeenEdition: stringField(subscription, "lastSeenEdition") || source.lastSeenEdition,
        lastSeenResolvedUriSummary:
          redactedPublicUri(stringField(subscription, "lastSeenResolvedUri")) ||
          source.lastSeenResolvedUriSummary,
        updateCount: numberField(subscription, "updateCount") || source.updateCount || 0,
        lastError: sourceErrorAfterSubscriptionUpdate(source, subscription, attentionStatus),
      });
    });
  }

  function allMessageSummaries() {
    return boundedImportedMessages(state.importedMessages, maxImportedMessages).concat(
      localOutboxSummaries()
    );
  }

  function localOutboxSummaries() {
    return state.localOutbox
      .map(localOutboxSummary)
      .filter((message) => message && isSafeMessageId(message.messageId))
      .slice(0, maxLocalOutboxMessages);
  }

  function localOutboxSummary(signedMessage) {
    const message =
      signedMessage && typeof signedMessage === "object" && !Array.isArray(signedMessage)
        ? signedMessage.message || {}
        : {};
    const messageId = rawString(message.messageId);
    if (!isSafeMessageId(messageId)) {
      return null;
    }
    return {
      messageId,
      authorFingerprint: boundedPreview(message.authorFingerprint, maxRecipientFingerprintLength),
      authorLabel: boundedPreview(message.authorLabel, maxAuthorLabelLength),
      profileUri: optionalCryptaContentUri(message.profileUri),
      channel: normalizeChannel(message.channel),
      subject: boundedPreview(message.subject, maxImportedSubjectLength) || "(no subject)",
      bodyPreview: boundedPreview(message.body, maxImportedBodyPreviewLength),
      bodySha256: "",
      createdAt: boundedPreview(message.createdAt, 64),
      replyTo: normalizeReplyReference(message.replyTo),
      tags: boundedTags(message.tags),
      sourceId: "local-outbox",
      sourceLabel: "local outbox",
      sourceUriHash: "",
      resolvedUri: "",
      signatureSha256: "",
      importedAt: boundedPreview(message.createdAt, 64),
      firstImportedAt: boundedPreview(message.createdAt, 64),
      lastSeenAt: boundedPreview(message.createdAt, 64),
      seenCount: 1,
      sourcesSeen: [boundedSourceSummary({ sourceId: "local-outbox", sourceLabel: "local outbox" })],
      local: true,
    };
  }

  function buildThreadIndex(messages, readStateValue) {
    const byId = new Map();
    for (const message of boundedArray(messages, maxImportedMessages + maxLocalOutboxMessages)) {
      if (message && isSafeMessageId(message.messageId)) {
        byId.set(message.messageId, boundedThreadMessage(message));
      }
    }
    const parentById = new Map();
    for (const message of byId.values()) {
      const parentId = normalizeReplyReference(message.replyTo);
      parentById.set(message.messageId, parentId && byId.has(parentId) ? parentId : "");
    }
    const rootCache = new Map();
    const rootFor = (message) => messageThreadRootId(message, byId, parentById, rootCache);
    const grouped = new Map();
    for (const message of byId.values()) {
      const rootId = rootFor(message);
      if (!grouped.has(rootId)) {
        grouped.set(rootId, []);
      }
      grouped.get(rootId).push(message);
    }
    const threads = [];
    for (const [rootId, threadMessages] of grouped.entries()) {
      const sortedMessages = threadMessages.slice().sort(messageSortCompare);
      const children = new Map();
      for (const message of sortedMessages) {
        children.set(message.messageId, []);
      }
      for (const message of sortedMessages) {
        const parentId = parentById.get(message.messageId);
        if (
          parentId &&
          parentId !== message.messageId &&
          rootFor(byId.get(parentId)) === rootId &&
          !wouldCreateThreadCycle(message.messageId, parentId, parentById)
        ) {
          children.get(parentId).push(message);
        }
      }
      for (const childList of children.values()) {
        childList.sort(messageSortCompare);
      }
      const rootMessage = byId.get(rootId) || sortedMessages[0];
      const thread = {
        rootId,
        rootMessage,
        messages: sortedMessages,
        children,
        latestAt: latestMessageTimestamp(sortedMessages),
        channel: normalizeChannel(rootMessage && rootMessage.channel),
        pinned: sortedMessages.some((message) => readStateValueFor(message, readStateValue).pinned),
        archived: sortedMessages.every((message) => readStateValueFor(message, readStateValue).archived),
        hasArchived: sortedMessages.some((message) => readStateValueFor(message, readStateValue).archived),
        totalMessages: sortedMessages.length,
        unreadMessages: threadUnreadCount(sortedMessages, readStateValue),
        sourceCount: threadSourceCount(sortedMessages),
      };
      threads.push(thread);
    }
    threads.sort((left, right) => threadSortKey(left).localeCompare(threadSortKey(right)));
    return { byId, threads };
  }

  function boundedThreadMessage(message) {
    return {
      messageId: message.messageId,
      authorFingerprint: boundedPreview(message.authorFingerprint, maxRecipientFingerprintLength),
      authorLabel: boundedPreview(message.authorLabel, maxAuthorLabelLength),
      profileUri: optionalCryptaContentUri(message.profileUri),
      channel: normalizeChannel(message.channel),
      subject: boundedPreview(message.subject, maxImportedSubjectLength) || "(no subject)",
      bodyPreview: boundedPreview(message.bodyPreview, maxImportedBodyPreviewLength),
      bodySha256: boundedPreview(message.bodySha256, 64),
      createdAt: boundedPreview(message.createdAt, 64),
      replyTo: normalizeReplyReference(message.replyTo),
      tags: boundedTags(message.tags),
      sourceId: boundedPreview(message.sourceId, 80),
      sourceLabel: boundedPreview(message.sourceLabel, maxSourceLabelLength),
      sourceUriHash: boundedPreview(message.sourceUriHash, 64),
      resolvedUri: boundedPreview(message.resolvedUri, maxSourceSummaryLength),
      signatureSha256: boundedPreview(message.signatureSha256, 64),
      importedAt: boundedPreview(message.importedAt, 64),
      firstImportedAt: boundedPreview(message.firstImportedAt || message.importedAt, 64),
      lastSeenAt: boundedPreview(message.lastSeenAt || message.importedAt, 64),
      seenCount: Math.max(1, numberField(message, "seenCount")),
      sourcesSeen: boundedSourceSummaries(message.sourcesSeen),
      local: Boolean(message.local),
    };
  }

  function messageThreadRootId(message, byId, parentById, rootCache) {
    if (!message || !isSafeMessageId(message.messageId)) {
      return "";
    }
    if (rootCache.has(message.messageId)) {
      return rootCache.get(message.messageId);
    }
    const path = [];
    const seen = new Map();
    let currentId = message.messageId;
    while (isSafeMessageId(currentId) && byId.has(currentId)) {
      if (seen.has(currentId)) {
        const cycleNodes = path.slice(seen.get(currentId));
        const rootId = cycleNodes.sort((left, right) => messageSortCompare(byId.get(left), byId.get(right)))[0];
        for (const id of path) {
          rootCache.set(id, rootId);
        }
        return rootId;
      }
      seen.set(currentId, path.length);
      path.push(currentId);
      const parentId = parentById.get(currentId);
      if (!parentId || !byId.has(parentId)) {
        for (const id of path) {
          rootCache.set(id, currentId);
        }
        return currentId;
      }
      currentId = parentId;
    }
    rootCache.set(message.messageId, message.messageId);
    return message.messageId;
  }

  function wouldCreateThreadCycle(messageId, parentId, parentById) {
    const seen = new Set([messageId]);
    let currentId = parentId;
    while (currentId) {
      if (seen.has(currentId)) {
        return true;
      }
      seen.add(currentId);
      currentId = parentById.get(currentId);
    }
    return false;
  }

  function threadSortKey(thread) {
    const pinnedRank = thread.pinned ? "0" : "1";
    const latestRank = String(9999999999999 - timestampMillis(thread.latestAt)).padStart(13, "0");
    return `${pinnedRank}|${latestRank}|${thread.rootId}`;
  }

  function messageSortKey(message) {
    return `${String(timestampMillis(message && message.createdAt)).padStart(13, "0")}|${
      (message && message.messageId) || ""
    }`;
  }

  function messageSortCompare(left, right) {
    return messageSortKey(left).localeCompare(messageSortKey(right));
  }

  function latestMessageTimestamp(messages) {
    let latest = "";
    let latestMillis = -1;
    for (const message of messages) {
      const millis = timestampMillis(message.createdAt);
      if (millis > latestMillis || (millis === latestMillis && message.messageId > latest)) {
        latestMillis = millis;
        latest = message.createdAt || latest;
      }
    }
    return latest;
  }

  function threadUnreadCount(messages, readStateValue) {
    return messages.filter(
      (message) =>
        !readStateValueFor(message, readStateValue).archived && !isMessageReadWithState(message, readStateValue)
    ).length;
  }

  function threadSourceCount(messages) {
    const sources = new Set();
    for (const message of messages) {
      for (const source of boundedSourceSummaries(message.sourcesSeen)) {
        const key = source.sourceUriHash || source.sourceId || source.sourceLabel;
        if (key) {
          sources.add(key);
        }
      }
      if (message.sourceUriHash || message.sourceId || message.local) {
        sources.add(message.sourceUriHash || message.sourceId || "local-outbox");
      }
    }
    return sources.size;
  }

  function filterThreads(threads) {
    const query = normalizedSearchQuery();
    const selectedChannelName = selectedChannel();
    return threads.filter((thread) => {
      if (
        selectedChannelName &&
        !thread.messages.some((message) => normalizeChannel(message.channel) === selectedChannelName)
      ) {
        return false;
      }
      if (state.readFilter === "active" && thread.archived) {
        return false;
      }
      if (state.readFilter === "unread" && (thread.archived || thread.unreadMessages === 0)) {
        return false;
      }
      if (state.readFilter === "archived" && !thread.hasArchived) {
        return false;
      }
      return !query || threadContainsMessage(thread, query);
    });
  }

  function threadContainsMessage(thread, query) {
    return thread.messages.some((message) => searchableMessageText(message).includes(query));
  }

  function searchableMessageText(message) {
    return [
      message.subject,
      message.authorLabel,
      message.authorFingerprint,
      fingerprintSummary(message.authorFingerprint),
      message.channel,
      message.bodyPreview,
      boundedTags(message.tags).join(" "),
      message.sourceLabel,
      boundedSourceSummaries(message.sourcesSeen)
        .map((source) => source.sourceLabel)
        .join(" "),
    ]
      .join(" ")
      .toLowerCase();
  }

  function discoveredChannels() {
    const values = new Set();
    for (const message of allMessageSummaries()) {
      values.add(normalizeChannel(message.channel));
    }
    return Array.from(values).sort((left, right) => left.localeCompare(right)).slice(0, 80);
  }

  function selectedChannel() {
    return normalizeChannelFilter(state.channelFilter);
  }

  function updateChannelFilter() {
    state.channelFilter = normalizeChannelFilter(elements.channelFilter.value);
    persistUiState().catch((error) => setStatus(CryptaPlatform.api.errorMessage(error), "error"));
    renderInbox();
  }

  function updateReadFilter() {
    state.readFilter = normalizeReadFilter(elements.readFilter.value);
    persistUiState().catch((error) => setStatus(CryptaPlatform.api.errorMessage(error), "error"));
    renderInbox();
  }

  function updateSearchQuery() {
    state.searchQuery = boundedSearchQuery(elements.searchInput.value);
    renderInbox();
  }

  function clearSearchQuery() {
    state.searchQuery = "";
    elements.searchInput.value = "";
    renderInbox();
  }

  function prepareReply(message) {
    if (!message || !isSafeMessageId(message.messageId)) {
      return;
    }
    setFieldValue(elements.composeForm, "replyTo", message.messageId);
    setFieldValue(elements.composeForm, "channel", normalizeChannel(message.channel));
    if (!fieldValue(elements.composeForm, "subject") && message.subject) {
      const subject = message.subject.toLowerCase().startsWith("re:")
        ? message.subject
        : `Re: ${message.subject}`;
      setFieldValue(elements.composeForm, "subject", boundedPreview(subject, maxImportedSubjectLength));
    }
    renderReplyContext();
    elements.composeForm.elements.namedItem("body").focus();
    setStatus("Reply target selected without copying the parent body.");
  }

  function clearReplyContext() {
    setFieldValue(elements.composeForm, "replyTo", "");
    renderReplyContext();
  }

  function renderReplyContext() {
    elements.replyContext.replaceChildren();
    const replyTo = normalizeReplyReference(fieldValue(elements.composeForm, "replyTo"));
    elements.clearReplyButton.disabled = !replyTo;
    if (!replyTo) {
      elements.replyContext.append(empty("No reply target selected."));
      return;
    }
    const parent = findMessageSummaryById(replyTo);
    if (!parent) {
      elements.replyContext.append(
        summaryRow("Reply target", `${replyTo} / parent not imported locally`)
      );
      return;
    }
    elements.replyContext.append(
      summaryRow("Reply subject", parent.subject || "(no subject)"),
      summaryRow(
        "Parent author",
        `${parent.authorLabel || "Unknown author"} / ${fingerprintSummary(parent.authorFingerprint)}`
      ),
      summaryRow("Created", parent.createdAt),
      summaryRow("Message", parent.messageId)
    );
  }

  function findMessageSummaryById(messageId) {
    return allMessageSummaries().find((message) => message.messageId === messageId) || null;
  }

  async function copyProfileUri(profileUri) {
    const safeUri = optionalCryptaContentUri(profileUri);
    if (!safeUri) {
      setStatus("Profile URI is not a valid Crypta content key.", "error");
      return;
    }
    if (!navigator.clipboard || typeof navigator.clipboard.writeText !== "function") {
      setStatus("Profile URI is shown above; clipboard is unavailable.", "warning");
      return;
    }
    try {
      await navigator.clipboard.writeText(safeUri);
      setStatus("Profile URI copied.");
    } catch (error) {
      setStatus("Profile URI is shown above; clipboard write was denied.", "warning");
    }
  }

  function selectedIdentity() {
    return state.identities.find((identity) => identityId(identity) === state.selectedIdentityId);
  }

  function identityId(identity) {
    return stringField(identity, "identityId", "id");
  }

  function identityLabel(identity) {
    return (
      boundedPreview(stringField(identity, "label", "name"), maxAuthorLabelLength) ||
      boundedPreview(identityId(identity), maxAuthorLabelLength) ||
      "Identity"
    );
  }

  function subscriptionId(subscription) {
    return stringField(subscription, "subscriptionId", "id");
  }

  function subscriptionForSource(source) {
    return state.subscriptions.find((subscription) => subscriptionId(subscription) === source.subscriptionId);
  }

  function subscriptionStatusCode(subscription) {
    const rawStatus = stringField(subscription, "status", "state");
    return rawStatus.toLowerCase().replace(/-/g, "_");
  }

  function subscriptionErrorCode(subscription) {
    const rawCode = stringField(subscription, "lastErrorCode", "errorCode");
    return rawCode.toLowerCase().replace(/-/g, "_");
  }

  function subscriptionStatusSummary(subscription) {
    const code = subscriptionStatusCode(subscription);
    const errorCode = subscriptionErrorCode(subscription);
    if (
      errorCode === "content_subscription_budget_exhausted" ||
      errorCode === "content_subscription_concurrency_limited"
    ) {
      return "Budget exhausted";
    }
    return subscriptionStatusLabels[code] || boundedPreview(stringField(subscription, "status", "state"), 80);
  }

  function subscriptionAttentionStatusSummary(subscription) {
    const code = subscriptionStatusCode(subscription);
    const summary = subscriptionStatusSummary(subscription);
    if (summary === "Budget exhausted") {
      return summary;
    }
    return ["queue_pressure", "runtime_unavailable", "backoff", "budget_exhausted"].includes(code)
      ? summary
      : "";
  }

  function sourceStatusAfterSubscriptionUpdate(source, attentionStatus) {
    if (attentionStatus) {
      return attentionStatus;
    }
    if (isSubscriptionAttentionStatus(source.lastStatus)) {
      return source.subscriptionId ? "Subscribed" : "";
    }
    return source.lastStatus;
  }

  function sourceErrorAfterSubscriptionUpdate(source, subscription, attentionStatus) {
    const errorSummary = subscriptionErrorSummary(subscription);
    if (errorSummary) {
      return errorSummary;
    }
    if (attentionStatus || isSubscriptionAttentionStatus(source.lastError)) {
      return "";
    }
    return source.lastError;
  }

  function isSubscriptionAttentionStatus(status) {
    return ["Queue pressure", "Runtime unavailable", "Backoff", "Budget exhausted"].includes(status);
  }

  function subscriptionRetrySummary(subscription) {
    return stringField(
      subscription,
      "nextCheckAt",
      "nextPollAt",
      "nextDueAt",
      "nextAvailableAt",
      "nextRetryAt",
    );
  }

  function subscriptionErrorSummary(subscription) {
    const attentionStatus = subscriptionAttentionStatusSummary(subscription);
    if (attentionStatus) {
      return attentionStatus;
    }
    if (subscriptionStatusSummary(subscription) === "Budget exhausted") {
      return "Budget exhausted";
    }
    return stringField(subscription, "lastError", "lastErrorCode", "errorSummary");
  }

  function sourceFetchUri(source) {
    const subscription = subscriptionForSource(source);
    return normalizedCryptaContentUri(
      stringField(subscription, "lastSeenResolvedUri", "resolvedUri", "sourceUri", "uri"),
      ["USK"],
    );
  }

  function readState(message) {
    const messageId = message && rawString(message.messageId);
    if (!isSafeMessageId(messageId)) {
      return {};
    }
    return state.readState[messageId] || {};
  }

  function readStateValueFor(message, readStateValue) {
    const messageId = message && rawString(message.messageId);
    if (!isSafeMessageId(messageId)) {
      return {};
    }
    const source =
      readStateValue && typeof readStateValue === "object" && !Array.isArray(readStateValue)
        ? readStateValue
        : state.readState;
    return source[messageId] || {};
  }

  function isMessageRead(message) {
    return isMessageReadWithState(message, state.readState);
  }

  function isMessageReadWithState(message, readStateValue) {
    const itemState = readStateValueFor(message, readStateValue);
    if (Object.prototype.hasOwnProperty.call(itemState, "read")) {
      return Boolean(itemState.read);
    }
    return Boolean(message && message.local);
  }

  function messageDraftFromForm(formData) {
    return {
      channel: normalizeChannel(textValue(formData, "channel")),
      subject: boundedPreview(textValue(formData, "subject"), 160),
      body: textValue(formData, "body"),
      authorLabel: boundedPreview(fieldValue(elements.profileForm, "authorLabel"), maxAuthorLabelLength),
      profileUri: optionalCryptaContentUri(fieldValue(elements.profileForm, "profileUri")),
      replyTo: normalizeReplyReference(textValue(formData, "replyTo")),
      recipientFingerprint: textValue(formData, "recipientFingerprint"),
      tags: tagsFromText(textValue(formData, "tags")),
    };
  }

  function boundedDraft(message) {
    return {
      channel: normalizeChannel(message.channel),
      subject: boundedPreview(message.subject, 160),
      body: boundedPreview(message.body, maxDraftBodyLength),
      replyTo: normalizeReplyReference(message.replyTo),
      recipientFingerprint: boundedPreview(message.recipientFingerprint, 128),
      tags: boundedTags(message.tags),
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
      label: boundedPreview(source.label, maxSourceLabelLength) || "Social source",
      uriHash: boundedPreview(source.uriHash, 64),
      uriSummary:
        boundedPreview(source.uriSummary, maxSourceSummaryLength) || "USK social source URI redacted",
      subscriptionId: boundedPreview(source.subscriptionId, 120),
      lastCheckedAt: boundedPreview(source.lastCheckedAt, 64),
      lastStatus: boundedPreview(source.lastStatus, 80),
      lastSubscriptionStatus: boundedPreview(source.lastSubscriptionStatus, 80),
      lastSubscriptionRetry: boundedPreview(source.lastSubscriptionRetry, 64),
      lastSeenEdition: boundedPreview(source.lastSeenEdition, 40),
      lastSeenResolvedUriSummary: boundedPreview(
        source.lastSeenResolvedUriSummary,
        maxSourceSummaryLength,
      ),
      updateCount: Math.max(0, numberField(source, "updateCount")),
      lastError: boundedPreview(source.lastError, 160),
    }));
  }

  function boundedArray(value, limit) {
    return Array.isArray(value) ? value.slice(0, limit) : [];
  }

  function stringListField(object, name, limit) {
    if (!object || typeof object !== "object" || !Array.isArray(object[name])) {
      return [];
    }
    return object[name].map(stringValue).filter((value) => value).slice(0, limit);
  }

  function boundedImportedMessages(value, limit) {
    return boundedArray(value, limit).map(boundedImportedMessage).filter(Boolean);
  }

  function boundedImportedMessage(message) {
    if (!message || typeof message !== "object" || !isSafeMessageId(message.messageId)) {
      return null;
    }
    return {
      messageId: message.messageId,
      authorFingerprint: boundedPreview(message.authorFingerprint, maxRecipientFingerprintLength),
      authorLabel: boundedPreview(message.authorLabel, maxAuthorLabelLength),
      profileUri: optionalCryptaContentUri(message.profileUri),
      channel: normalizeChannel(message.channel),
      subject: boundedPreview(message.subject, maxImportedSubjectLength) || "(no subject)",
      bodyPreview: boundedPreview(message.bodyPreview, maxImportedBodyPreviewLength),
      bodySha256: boundedPreview(message.bodySha256, 64),
      createdAt: boundedPreview(message.createdAt, 64),
      replyTo: normalizeReplyReference(message.replyTo),
      tags: boundedTags(message.tags),
      sourceId: boundedPreview(message.sourceId, 80),
      sourceLabel: boundedPreview(message.sourceLabel, maxSourceLabelLength),
      sourceUriHash: boundedPreview(message.sourceUriHash, 64),
      resolvedUri: boundedPreview(message.resolvedUri, maxSourceSummaryLength),
      signatureSha256: boundedPreview(message.signatureSha256, 64),
      importedAt: boundedPreview(message.importedAt, 64),
      firstImportedAt: boundedPreview(message.firstImportedAt || message.importedAt, 64),
      lastSeenAt: boundedPreview(message.lastSeenAt || message.importedAt, 64),
      seenCount: Math.max(1, numberField(message, "seenCount")),
      sourcesSeen: boundedSourceSummaries(message.sourcesSeen),
    };
  }

  function boundedReadState(value, limit) {
    const source = value && typeof value === "object" && !Array.isArray(value) ? value : {};
    const result = Object.create(null);
    let count = 0;
    for (const key of Object.keys(source)) {
      if (!isSafeMessageId(key)) {
        continue;
      }
      const item = source[key];
      if (!item || typeof item !== "object" || Array.isArray(item)) {
        continue;
      }
      const entry = boundedReadStateEntry(item);
      if (Object.keys(entry).length === 0) {
        continue;
      }
      result[key] = entry;
      count += 1;
      if (count >= limit) {
        break;
      }
    }
    return result;
  }

  function boundedReadStateEntry(item) {
    const entry = Object.create(null);
    if (Object.prototype.hasOwnProperty.call(item, "read")) {
      entry.read = Boolean(item.read);
    }
    if (item.pinned) {
      entry.pinned = true;
    }
    if (item.archived) {
      entry.archived = true;
    }
    const lastViewedAt = boundedPreview(item.lastViewedAt, 64);
    if (lastViewedAt) {
      entry.lastViewedAt = lastViewedAt;
    }
    return entry;
  }

  function isSafeMessageId(value) {
    return typeof value === "string" && messageIdPattern.test(value);
  }

  function normalizeReplyReference(value) {
    const text = boundedPreview(value, maxMessageReferenceLength);
    return isSafeMessageId(text) ? text : "";
  }

  function normalizeChannel(value) {
    const text = boundedPreview(value, maxImportedChannelLength).toLowerCase();
    if (!text || /[\s\\/\u0000]/.test(text)) {
      return "general";
    }
    return text;
  }

  function normalizeChannelFilter(value) {
    const text = stringValue(value);
    return text ? normalizeChannel(text) : "";
  }

  function normalizeReadFilter(value) {
    return ["active", "unread", "archived", "all"].includes(value) ? value : "active";
  }

  function boundedSearchQuery(value) {
    return boundedPreview(value, maxSearchQueryLength);
  }

  function normalizedSearchQuery() {
    return boundedSearchQuery(state.searchQuery).toLowerCase();
  }

  function boundedTags(tags) {
    return boundedArray(tags, maxTagCount)
      .map((tag) => boundedPreview(tag, maxTagLength))
      .filter((tag) => tag);
  }

  function tagsFromText(value) {
    return stringValue(value)
      .split(",")
      .map((tag) => tag.trim())
      .filter((tag) => tag)
      .map((tag) => boundedPreview(tag, maxTagLength))
      .slice(0, maxTagCount);
  }

  function boundedSourceSummaries(sourcesSeen) {
    return boundedArray(sourcesSeen, maxSourcesPerMessage).map(boundedSourceSummary);
  }

  function sourceCountForMessage(message) {
    const sources = boundedSourceSummaries(message && message.sourcesSeen);
    if (sources.length > 0) {
      return sources.length;
    }
    return message && (message.sourceUriHash || message.sourceId || message.local) ? 1 : 0;
  }

  function fingerprintSummary(value) {
    const text = boundedPreview(value, maxRecipientFingerprintLength);
    if (text.length <= 18) {
      return text || "unknown fingerprint";
    }
    return `${text.slice(0, 12)}...${text.slice(-6)}`;
  }

  function timestampMillis(value) {
    const parsed = Date.parse(stringValue(value));
    return Number.isFinite(parsed) ? parsed : 0;
  }

  function earliestTimestamp(left, right) {
    const leftMillis = timestampMillis(left);
    const rightMillis = timestampMillis(right);
    if (!leftMillis) {
      return boundedPreview(right, 64);
    }
    if (!rightMillis) {
      return boundedPreview(left, 64);
    }
    return leftMillis <= rightMillis ? boundedPreview(left, 64) : boundedPreview(right, 64);
  }

  function latestTimestamp(left, right) {
    const leftMillis = timestampMillis(left);
    const rightMillis = timestampMillis(right);
    if (!leftMillis) {
      return boundedPreview(right, 64);
    }
    if (!rightMillis) {
      return boundedPreview(left, 64);
    }
    return leftMillis >= rightMillis ? boundedPreview(left, 64) : boundedPreview(right, 64);
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
    return !!normalizedCryptaContentUri(uri, ["USK"]);
  }

  function optionalCryptaContentUri(value, allowedKinds) {
    const text = stringValue(value);
    if (!text) {
      return "";
    }
    return normalizedCryptaContentUri(text, allowedKinds || ["CHK", "SSK", "USK", "KSK"]);
  }

  function normalizedCryptaContentUri(value, allowedKinds) {
    const uri = stringValue(value);
    if (
      !uri ||
      uri.length > maxProfileUriLength ||
      /[\s\\\u0000]/.test(uri) ||
      uri.includes("?") ||
      uri.includes("#")
    ) {
      return "";
    }
    const runtimeUri = uri.toLowerCase().startsWith("crypta:") ? uri.slice(7).trim() : uri;
    if (!runtimeUri || runtimeUri.startsWith("/") || runtimeUri.startsWith("\\")) {
      return "";
    }
    const colon = runtimeUri.indexOf(":");
    const at = runtimeUri.indexOf("@");
    if (colon >= 0 && (at < 0 || colon < at)) {
      return "";
    }
    const upper = runtimeUri.toUpperCase();
    return allowedKinds.some(
      (kind) => upper.startsWith(`${kind}@`) && runtimeUri.length > kind.length + 1,
    )
      ? uri
      : "";
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
    if (normalizedCryptaContentUri(value, ["USK"])) {
      return "USK social source URI redacted";
    }
    if (normalizedCryptaContentUri(value, ["CHK"])) {
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
    span.textContent = boundedPreview(value, maxDisplayTextLength) || "not available";
    row.append(strong, span);
    return row;
  }

  function headingText(value, level) {
    const heading = document.createElement(level);
    heading.textContent = boundedPreview(value, maxImportedSubjectLength) || "Untitled";
    return heading;
  }

  function paragraph(className, value) {
    const node = document.createElement("p");
    node.className = className;
    node.textContent = boundedPreview(
      value,
      className === "message-body" ? maxImportedBodyPreviewLength : maxDisplayTextLength,
    );
    return node;
  }

  function badges(values, mode) {
    const container = document.createElement("div");
    container.className = "message-badges";
    for (const value of values.filter((item) => stringValue(item))) {
      const badge = document.createElement("span");
      badge.className = `badge badge--${mode || "neutral"}`;
      badge.textContent = boundedPreview(value, maxDisplayTextLength);
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
    node.textContent = boundedPreview(text, maxDisplayTextLength);
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

  function optionalNumberField(object, ...names) {
    if (!object || typeof object !== "object") {
      return null;
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
    return null;
  }

  function boundedPreview(value, maxLength) {
    const text = stringValue(value).replace(unsafeControlPattern(), " ");
    if (text.length <= maxLength) {
      return text;
    }
    return text.slice(0, Math.max(0, maxLength - 3)) + "...";
  }

  function unsafeControlPattern() {
    return /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g;
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
    elements.status.textContent = boundedPreview(message, maxDisplayTextLength);
    elements.status.dataset.tone = tone || "default";
  }
})();
