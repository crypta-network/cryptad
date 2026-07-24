"""Implementation segment for the selftest workspace portion of ``app_platform_smoke.py``."""

from __future__ import annotations

def make_self_test_workspace(workspace: Path) -> None:
    sdk = workspace / 'platform-sdk-js/src/main/resources/network/crypta/platform/sdk/js/crypta-platform.js'
    sdk.parent.mkdir(parents=True, exist_ok=True)
    sdk.write_text("const contentFormats = Object.freeze({ profileDocument: Object.freeze({ id: 'crypta.profile.v1', schema: 'crypta.profile.v1', contentType: 'application/vnd.crypta.profile+json', defaultFilename: 'profile.json', majorVersion: 1, status: 'experimental', signed: true, signingDomain: 'profile.publish.v1', unknownFieldPolicy: 'reject_unknown_fields', futureVersionPolicy: 'reject_unknown_major_accept_known_minor_only', deprecationPolicy: 'explicit_warning_or_reject' }), feedSnapshot: Object.freeze({ id: 'crypta.feed.snapshot.v1', type: 'crypta.feed.snapshot.v1', contentType: 'application/vnd.crypta.feed+json', defaultFilename: 'feed.json', maxDocumentBytes: 65536, signed: false }), trustStatement: Object.freeze({ id: 'crypta.trust.statement.v1', type: 'crypta.trust.statement.v1', contentType: 'application/vnd.crypta.trust+json', defaultFilename: 'trust.json', signed: true, signingDomain: 'crypta.trust.statement.v1' }), socialMessage: Object.freeze({ id: 'crypta.social.message.v1', type: 'crypta.social.message.v1', contentType: 'application/json', signed: true, signingDomain: 'crypta.social.message.v1' }), socialOutbox: Object.freeze({ id: 'crypta.social.outbox.v1', type: 'crypta.social.outbox.v1', contentType: 'application/vnd.crypta.social.outbox+json', defaultFilename: 'social-outbox.json', maxDocumentBytes: 65536, signed: false }) }); const profileContentType = contentFormats.profileDocument.contentType; const feedSnapshotContentType = contentFormats.feedSnapshot.contentType; const feedSnapshotMaxDocumentBytes = contentFormats.feedSnapshot.maxDocumentBytes; const trustContentType = contentFormats.trustStatement.contentType; const socialOutboxContentType = contentFormats.socialOutbox.contentType; window.CryptaPlatform = { contentFormats, data: Object.freeze({ records: Object.freeze({ getJson(){}, putJson(){} }), export(){}, import(){} }), queue: { snapshot(){} }, trust: { score(){} }, services: Object.freeze({ list: listAppServices, get: getAppService, dependencies: Object.freeze({ list: listAppServiceDependencies, get: getAppServiceDependencies }), bundles: Object.freeze({ list: listAppServiceBundles, request: requestAppServiceBundle, approve: approveAppServiceBundle, reject: rejectAppServiceBundle, renew: renewAppServiceBundle }), grants: Object.freeze({ list: listAppServiceGrants, request: requestAppServiceGrant, revoke: revokeAppServiceGrant }), invoke: invokeAppService }), vault: { identities: { create(){}, list(){}, createProfileDocument(){}, createTrustStatement(){}, createSocialMessageDocument(){} } }, content: { insertAppDocument(){}, fetchText(){}, subscriptions: Object.freeze({ list(){}, create(){}, get(){}, refresh(){}, pause(){}, resume(){}, remove(){} }) } }; function putAppDataJson(){} function getAppDataJson(){} const appDataExportPath = 'app-data/export'; const appDataImportPath = 'app-data/import'; function trustStatus(){} function addTrustAnchor(){} function importTrustStatement(){} function previewTrustImport(){} function trustAnchorLifecycleRequest(){} CryptaPlatform.trust.previewImport = previewTrustImport; CryptaPlatform.trust.anchors = { deprecate: trustAnchorLifecycleRequest, revoke: trustAnchorLifecycleRequest, reactivate: trustAnchorLifecycleRequest }; function importTrustUri(){} function trustAudit(){} function trustScore(){} function getTrustStatement(){} function deprecateTrustStatement(){} function revokeTrustStatement(){} function reactivateTrustStatement(){} function normalizeTrustLifecycleMutation(){} const backupMarker = 'CryptaPlatform.data.export path-free backup export import preview'; const trustStatementRoute = 'trust-graph/statements/'; const subscriptionId = 'sub-redacted'; function publishTrustStatement(){} function fetchAndImportTrustStatement(){} function createTrustSubscription(){} function normalizeSocialMessageDocument(){} function listAppServices(){} function getAppService(){} function listAppServiceDependencies(){} function getAppServiceDependencies(){} function listAppServiceBundles(){} function requestAppServiceBundle(){} function approveAppServiceBundle(){} function rejectAppServiceBundle(){} function renewAppServiceBundle(){} function listAppServiceGrants(){} function requestAppServiceGrant(){} function revokeAppServiceGrant(){} function invokeAppService(){} const socialMessageRoute = '/social-message'; function createContentSubscription(){} function removeContentSubscription(){} function contentSubscriptionPathSegment(){} const path = 'content/subscriptions'; function apiDeleteForm(){} const h = 'X-Crypta-App-Session';\n", encoding='utf-8')
    design_dir = workspace / 'platform-design-system/src/main/resources/network/crypta/platform/designsystem/static'
    design_dir.mkdir(parents=True, exist_ok=True)
    (design_dir / 'crypta-ui-tokens.css').write_text(':root{--cr-space-4:1rem;}\n', encoding='utf-8')
    (design_dir / 'crypta-ui.css').write_text('.cr-app{}.cr-shell{}.cr-button{}\n', encoding='utf-8')
    (design_dir / 'crypta-ui-components.js').write_text('window.CryptaUi={version:"1"};\n', encoding='utf-8')
    for project, app_id, display_name, launcher, permissions, app_js in (('queue-manager', 'queue-manager', 'Queue Manager', 'queue-manager.sh', 'queue.read,queue.write', "CryptaPlatform.bootstrap.load({ appId: 'queue-manager' });\n"), ('publisher', 'publisher', 'Publisher', 'publisher.sh', 'queue.read,queue.write,content.insert', "CryptaPlatform.bootstrap.load({ appId: 'publisher' });\n"), ('site-publisher', 'site-publisher', 'Site Publisher', 'site-publisher.sh', 'queue.read,queue.write,content.insert', "const appId = 'site-publisher';\nCryptaPlatform.bootstrap.load({ appId });\nCryptaPlatform.content.insertDirectory(new FormData());\nCryptaPlatform.content.insertFile(new FormData());\nCryptaPlatform.queue.snapshot({ page: 'uploads' });\n"), ('profile-publisher', 'profile-publisher', 'Profile Publisher', 'profile-publisher.sh', 'queue.read,queue.write,content.insert.app-document,vault.identities.read,vault.identities.create,vault.identities.use,app.data.read,app.data.write', 'const appId = \'profile-publisher\';\nconst identityId = \'profile-self-test\';\nconst maxRecentActions = 5;\nconst maxProfileTextLength = 512; const maxProfileBioLength = 2048; const maxContentUriLength = 1024;\nfunction optionalProfileWebsite(value) { const website = String(value || \'\').trim(); return website.length > maxContentUriLength ? \'\' : website; }\nconst draft = { website: optionalProfileWebsite(\'https://example.org\') };\nconst dataNamespace = "profile-draft";\nconst dataStateKey = "publisher-state";\nconst activeMarkup = [\'srcdoc\', \'iframe\', \'base\', \'svg\']; const preview = { textContent: \'\' };\nCryptaPlatform.bootstrap.load({ appId });\nCryptaPlatform.data.records.getJson(\'profile-draft\', \'publisher-state\');\nCryptaPlatform.data.records.putJson({ namespace: \'profile-draft\', key: \'publisher-state\', schemaVersion: 1, value: { lastPublishedProfileUri: \'\', recentActions: [], selectedIdentityId: \'\' } });\nCryptaPlatform.api.postForm(\'app-vault/identities\', { label: \'Profile\' });\nCryptaPlatform.api.postForm(`app-vault/identities/${identityId}/profile-document`, { profile: \'redacted\' });\nCryptaPlatform.api.postForm(\'queue/inserts/app-document\', { document: \'redacted\' });\nCryptaPlatform.queue.snapshot({ page: \'uploads\' });\n'), ('feed-reader', 'feed-reader', 'Feed Reader & Publisher', 'feed-reader.sh', 'content.fetch,content.subscribe,content.insert.app-document,queue.read,queue.write,app.data.read,app.data.write', 'const appId = \'feed-reader\';\nconst maxSources = 12;\nconst maxRememberedSnapshots = 12;\nfunction normalizedCryptaContentUri(uri) { return String(uri).startsWith(\'USK@\') || String(uri).startsWith(\'crypta:USK@\') ? uri : null; }\nconst activeMarkup = [\'srcdoc\', \'iframe\', \'base\', \'svg\']; const feedNode = { textContent: \'\' };\nconst dataNamespace = "ui-state";\nconst dataStateKey = "reader-state";\nCryptaPlatform.bootstrap.load({ appId });\nCryptaPlatform.data.records.getJson(\'ui-state\', \'reader-state\');\nCryptaPlatform.data.records.putJson({ namespace: \'ui-state\', key: \'reader-state\', schemaVersion: 2, value: { lastPublisherDraft: {}, selectedSourceId: \'\', fetchedSnapshots: [] } });\nCryptaPlatform.content.subscriptions.list();\nCryptaPlatform.content.subscriptions.create({ uri: \'USK@redacted/feed/0/feed.json\', label: \'Feed\' });\nCryptaPlatform.content.subscriptions.refresh(\'sub-redacted\');\nCryptaPlatform.content.subscriptions.pause(\'sub-redacted\');\nCryptaPlatform.content.subscriptions.resume(\'sub-redacted\');\nCryptaPlatform.content.subscriptions.remove(\'sub-redacted\');\nconst lastSeenResolvedUri = \'USK@redacted/feed/0/feed.json\';\nCryptaPlatform.feed.fetchSnapshot({ uri: \'CHK@redacted\' });\nCryptaPlatform.content.fetchText({ uri: lastSeenResolvedUri });\nCryptaPlatform.feed.publishSnapshot({ snapshot: { type: \'crypta.feed.snapshot.v1\', items: [] } });\nCryptaPlatform.queue.snapshot({ page: \'uploads\' });\n'), ('social-inbox', 'social-inbox', 'Social Inbox RC', 'social-inbox.sh', 'vault.identities.read,vault.identities.create,vault.identities.use,content.fetch,content.subscribe,content.insert.app-document,queue.read,queue.write,app.data.read,app.data.write,app.services.read,app.services.call', 'const appId = \'social-inbox\';\nconst socialMessageType = CryptaPlatform.contentFormats.socialMessage.type;\nconst socialOutboxFormat = CryptaPlatform.contentFormats.socialOutbox;\nconst socialOutboxType = socialOutboxFormat.type;\nconst maxSources = 16;\nconst maxImportedMessages = 160;\nconst maxDraftBodyLength = 4096; const maxImportedSubjectLength = 160; const maxAuthorLabelLength = 120; const maxImportedChannelLength = 64;\nconst maxImportedBodyPreviewLength = 700;\nconst maxReadStateEntries = 240;\nconst maxMutedAuthors = 160;\nconst maxBlockedSources = 80;\nconst maxExportedMessages = 120;\nconst maxFetchedDocumentBytes = socialOutboxFormat.maxDocumentBytes;\nconst maxThreadDepth = 12;\nconst maxRenderedThreadMessages = 160;\nconst maxSearchQueryLength = 80;\nconst localFilters = { mutedAuthors: [], blockedSources: [] };\nfunction toggleMutedAuthor(message) { localFilters.mutedAuthors.push(message.authorFingerprint); }\nfunction toggleBlockedSource(source) { localFilters.blockedSources.push(source.sourceUriHash); }\nfunction isMessageLocallyHidden(message) { return localFilters.mutedAuthors.includes(message.authorFingerprint); }\nfunction visibleThreadMessages(thread) { return thread.messages.filter((message) => !isMessageLocallyHidden(message)); }\nfunction boundedExportSummary(kind, messages) { return { kind, maxExportedMessages, messageCount: messages.length, rawContentDiscarded: true }; }\nfunction exportVisibleMessages() { return boundedExportSummary(\'visible\', []); }\nfunction normalizedCryptaContentUri(uri) { return String(uri).startsWith(\'USK@\') || String(uri).startsWith(\'crypta:USK@\') ? uri : null; }\nconst socialNode = { textContent: \'\' };\nconst messageIdPattern = /^msg-[0-9a-f]{64}$/;\nconst channelFilter = \'all\'; const selectedChannel = \'general\'; const searchQuery = \'subject authorFingerprint bodyPreview sourceLabel\';\nfunction normalizeReplyReference(value) { return isSafeMessageId(value) ? value : \'\'; }\nfunction messageSortKey(message) { return `${message.createdAt}:${message.messageId}`; }\nfunction messageThreadRootId(message, byId) { const parent = normalizeReplyReference(message.replyTo); return parent && byId.get(parent) ? parent : message.messageId; }\nfunction threadSortKey(thread) { return `${thread.pinned}:${thread.latestCreatedAt}:${thread.rootId}`; }\nfunction threadUnreadCount(thread) { return thread.messages.filter((message) => !message.read).length; }\nfunction threadContainsMessage(thread, query) { return String(thread.subject + thread.authorLabel + thread.authorFingerprint + thread.channel + thread.bodyPreview + thread.sourceLabel).toLowerCase().includes(query); }\nfunction buildThreadIndex(messages, readState) { const byId = new Map(); const visiting = new Set(); const visited = new Set(); const cycleBreak = \'cycle detection\'; return { byId, visiting, visited, cycleBreak, readState }; }\nfunction renderThreadList(threads) { socialNode.textContent = \'\'; socialNode.replaceChildren(...threads.slice(0, maxRenderedThreadMessages)); }\nfunction markThreadRead(thread) { boundedReadState(thread.messages.map((message) => message.messageId)); }\nfunction markThreadUnread(thread) { boundedReadState(thread.messages.map((message) => message.messageId)); }\nfunction archiveThread(thread) { thread.messages.forEach((message) => isSafeMessageId(message.messageId)); }\nfunction toggleThreadPin(thread) { thread.pinned = !thread.pinned; }\nfunction copyProfileUri(uri) { return optionalCryptaContentUri(uri); }\nconst subscriptionStatusLabels = Object.freeze({ queue_pressure: "Queue pressure", runtime_unavailable: "Runtime unavailable", backoff: "Backoff", budget_exhausted: "Budget exhausted" });\nfunction subscriptionStatusSummary(subscription) { return subscriptionStatusLabels[subscription.status] || "Stale"; }\nfunction subscriptionAttentionStatusSummary(subscription) { return subscriptionStatusSummary(subscription); }\nfunction subscriptionRetrySummary(subscription) { return subscription.nextCheckAt; }\nasync function refreshAllActiveSources() { const activeSourceIds = state.sources.map((source) => source.id).slice(0, maxSources); for (const sourceId of activeSourceIds) { const source = { subscriptionId: sourceId }; await CryptaPlatform.content.subscriptions.refresh(source.subscriptionId); } }\nasync function refreshAllSources() { return \'Refresh all active sources\'; }\nconst threadSourceSummary = { seenCount: 1, firstImportedAt: \'2026-01-01T00:00:00Z\', lastSeenAt: \'2026-01-01T00:00:00Z\', sourcesSeen: [{ sourceUriHash: \'redacted\', sourceLabel: \'source\' }] };\nfunction sourceSummariesForDedupe(message) { return message.sourcesSeen || [{ sourceUriHash: \'redacted\' }]; }\nconst lastCheckedAt = \'2026-01-01T00:00:00Z\'; const lastSeenEdition = 1;\nconst records = { uiState: ["ui-state", "social-inbox"], sources: ["social", "sources"], outboxSummary: ["social", "outbox-summary"], importedMessageIndex: ["social", "imported-message-index"], readState: ["social", "read-state"], drafts: ["social", "drafts"], localFilters: ["social", "local-filters"] };\nconst dataSchemaVersion = 1;\nconst namespaceSchemaVersions = Object.freeze({ "ui-state": 1, social: dataSchemaVersion });\nfunction schemaVersionForRecord(record) { return namespaceSchemaVersions[record[0]] || dataSchemaVersion; }\nasync function putJsonRecord(record, value) { return CryptaPlatform.data.records.putJson({ namespace: record[0], key: record[1], schemaVersion: schemaVersionForRecord(record), value }); }\nCryptaPlatform.bootstrap.load({ appId });\nCryptaPlatform.vault.identities.list();\nCryptaPlatform.vault.identities.create({ label: \'Social\' });\nCryptaPlatform.vault.identities.createProfileDocument(\'social-self-test\', { displayName: \'Social\' });\nCryptaPlatform.vault.identities.createSocialMessageDocument(\'social-self-test\', { body: \'redacted\' });\nfunction ensureSignedSocialMessage(value) { const signature = value.signature || {}; if (signature.domain !== socialMessageType) throw new Error(); }\nasync function verifySocialMessageSignature(value) { const signature = value.signature || {}; const message = value.message || {}; if (signature.publicKeyFingerprint !== message.authorFingerprint) throw new Error(); const expected = await expectedSocialMessageId(message); if (message.messageId !== expected) throw new Error(\'Social message id does not match canonical payload.\'); const publicKeyBytes = decodeBase64(signature.publicKeyBase64, \'publicKeyBase64\'); const publicKeyFingerprint = await sha256Hex(publicKeyBytes); if (publicKeyFingerprint !== stringValue(signature.publicKeyFingerprint)) throw new Error(); return window.crypto.subtle.verify(); }\nfunction canonicalSocialMessagePayload(value) { return value; }\nfunction canonicalSocialMessageIdPayload(value) { return value; }\nasync function expectedSocialMessageId(value) { return \'msg-\' + await sha256Hex(canonicalSocialMessageIdPayload(value)); }\nfunction requireIsoTimestamp(value) { return value; }\nCryptaPlatform.content.insertAppDocument({ document: { type: socialOutboxType }, contentType: \'application/vnd.crypta.social.outbox+json\', targetFilename: \'social-outbox.json\' });\nCryptaPlatform.content.fetchText({ uri: \'USK@redacted/social/0/social-outbox.json\', maxBytes: maxFetchedDocumentBytes });\nCryptaPlatform.content.subscriptions.list();\nCryptaPlatform.content.subscriptions.create({ uri: \'USK@redacted/social/0/social-outbox.json\' });\nCryptaPlatform.content.subscriptions.refresh(\'sub-redacted\');\nCryptaPlatform.content.subscriptions.pause(\'sub-redacted\');\nCryptaPlatform.content.subscriptions.resume(\'sub-redacted\');\nCryptaPlatform.content.subscriptions.remove(\'sub-redacted\');\nconst lastSeenResolvedUri = \'USK@redacted/social/0/social-outbox.json\'; const updateCount = 1; const lastError = \'\';\nfunction isSocialSourceUri(uri) { return uri.startsWith(\'USK@\') || uri.startsWith(\'crypta:USK@\'); }\nfunction parseJsonObject(value) { return JSON.parse(value); }\nfunction boundedDrafts(value) { return value; }\nfunction isSafeMessageId(value) { return messageIdPattern.test(value); }\nfunction boundedReadState(value) { return Object.create(null); }\nfunction optionalNumberField(value) { return 0; }\nfunction normalizeTrustScore(score) { const trustStatus = \'unknown\'; const contributingEvidenceCount = 0; if (["trusted", "distrusted", "mixed"].includes(trustStatus)) return { status: "scored" }; return { status: "unscored", summary: "No local trust evidence." }; }\nfunction markTrustScoresUnavailable(summary) { return summary; }\nasync function publishOutbox() { const summary = {}; await persistOutboxSummary(summary); }\nconst bodySha256 = \'redacted\'; const bodyPreview = \'redacted\'; const signatureSha256 = \'redacted\';\nconst uriHash = \'redacted\'; const uriSummary = \'USK source URI redacted\'; const publicSourceUriHash = \'redacted\'; const publicSourceUriSummary = \'redacted\';\nconst insertUriRedaction = \'redacted\'; function redactedInsertUri(value) { return \'redacted\'; }\nCryptaPlatform.data.records.getJson(\'ui-state\', \'social-inbox\');\nCryptaPlatform.data.records.putJson({ namespace: \'social\', key: \'sources\', schemaVersion: schemaVersionForRecord([\'social\', \'sources\']), value: [] });\nconst trustScoreProviderAppId = "trust-graph"; const trustScoreServiceId = "trust.score"; const trustScoreContext = "message-author";\nCryptaPlatform.services.get(trustScoreProviderAppId, trustScoreServiceId);\nCryptaPlatform.services.grants.list();\nCryptaPlatform.services.bundles.request({ bundleAlias: "trust-annotations", includeOptional: true, purpose: \'Annotate message authors.\' });\nCryptaPlatform.services.invoke(trustScoreProviderAppId, trustScoreServiceId, { subjectKind: "identity", subjectUri: \'fingerprint\', context: trustScoreContext, scope: \'score.read\' });\nconst authorLabel = \'author\'; const authorFingerprint = \'fingerprint\'; const profileUri = \'crypta:USK@redacted/profile/0/profile.json\'; const trustGrantRequired = \'Trust score unavailable / grant required.\'; const trustGrantRevoked = \'Trust score unavailable / grant revoked.\'; const trustGrantExpired = \'Trust score unavailable / grant expired.\'; const trustGrantRevalidation = \'Trust score unavailable / grant requires operator revalidation.\'; const evidenceCount = 0;\nconst grantStatusRevalidation = \'revalidation-required\'; const grantRevokedLabel = \'grant revoked\';\nCryptaPlatform.queue.snapshot({ page: \'uploads\' });\nconst dataRecords = \'data.records\'; const contentSubscriptions = \'content.subscriptions\'; const serviceInvocation = \'services.invoke\'; const trustScore = \'trust.score\';\n'), ('trust-graph', 'trust-graph', 'Trust Graph Local RC', 'trust-graph.sh', 'trust.read,trust.write,content.fetch,content.subscribe,content.insert.app-document,queue.read,queue.write,vault.identities.read,vault.identities.create,vault.identities.use,app.data.read,app.data.write', 'const appId = \'trust-graph\';\nconst dataNamespace = "ui-state";\nconst dataStateKey = "preview-state";\nCryptaPlatform.bootstrap.load({ appId });\nfunction normalizeImportSummary(value) { return value; }\nfunction publicationSummary(value) { return value; }\nfunction queueSnapshotSummary(value) { return value; }\nfunction redactedUri(value) { return value; }\nfunction renderQueue(snapshot) { publicationSummary(snapshot); queueSnapshotSummary(snapshot); }\nfunction renderAudit() {}\nfunction renderSubscriptions() {}\nconst state = { recentImports: [], auditEvents: [], subscriptions: [], pendingImport: null, lastDraft: {} };\nfunction clearPendingImport() { state.pendingImport = null; }\nCryptaPlatform.data.records.getJson(\'ui-state\', \'preview-state\');\nCryptaPlatform.data.records.putJson({ namespace: \'ui-state\', key: \'preview-state\', schemaVersion: 2, value: { lastDraft: {}, recentImports: [] } });\nCryptaPlatform.trust.status();\nCryptaPlatform.trust.anchors.list();\nCryptaPlatform.trust.anchors.deprecate(\'anchor-fingerprint\', { reasonCode: \'local-policy\' });\nCryptaPlatform.trust.anchors.revoke(\'anchor-fingerprint\', { reasonCode: \'local-policy\' });\nCryptaPlatform.trust.anchors.reactivate(\'anchor-fingerprint\');\nconst importPreview = CryptaPlatform.trust.previewImport({ uri: \'CHK@redacted\', maxBytes: 65536, sourceLabel: \'self-test\' });\nconst expectedDocumentFingerprint = \'doc-fingerprint\';\nfunction commitPendingImport() { return CryptaPlatform.trust.exchange.fetchAndImport({ uri: \'CHK@redacted\', expectedDocumentFingerprint }); }\nconst previewSummary = { candidateStatementCount: 1, duplicateIssuerCount: 1, conflictCount: 1, rawContentDiscarded: true };\nconst duplicateIssuer = previewSummary.duplicateIssuerCount; const conflictStatus = \'conflict\';\nCryptaPlatform.trust.importStatement({ document: \'{}\' });\nCryptaPlatform.trust.audit.list({ limit: 12 });\nCryptaPlatform.trust.score({ subjectKind: \'profile\', subjectUri: \'USK@redacted\', context: \'profile\' });\nCryptaPlatform.trust.statements.get(\'fingerprint\');\nCryptaPlatform.trust.statements.deprecate(\'fingerprint\', { reasonCode: \'local-policy\' });\nCryptaPlatform.trust.statements.revoke(\'fingerprint\', { reasonCode: \'local-policy\' });\nCryptaPlatform.trust.statements.reactivate(\'fingerprint\');\nconst nonContributingReasons = [\'revoked\']; const evidenceTruncated = true;\nCryptaPlatform.trust.exchange.publish({ identityId: \'trust-self-test\', subjectKind: \'profile\', subjectUri: \'USK@redacted\', context: \'profile\', score: 50, confidence: 80, insertUri: \'USK@redacted\', identifier: \'trust\' });\nCryptaPlatform.trust.exchange.subscriptions.list();\nCryptaPlatform.trust.exchange.subscriptions.create({ uri: \'USK@redacted/trust/0/trust.json\' });\nCryptaPlatform.trust.exchange.subscriptions.refresh(\'sub-redacted\');\nCryptaPlatform.trust.exchange.subscriptions.pause(\'sub-redacted\');\nCryptaPlatform.trust.exchange.subscriptions.resume(\'sub-redacted\');\nCryptaPlatform.trust.exchange.subscriptions.remove(\'sub-redacted\');\nlastDraft.publish = { authorIdentity: \'trust-self-test\', subjectKind: \'profile\', subjectIdentity: \'USK@redacted\', value: 50, context: \'profile\' };\nCryptaPlatform.queue.snapshot({ page: \'uploads\' });\n')):
        source = workspace / f'apps/{project}/src/staged'
        staged = workspace / f'apps/{project}/build/cryptad-app/{app_id}'
        for root in (source, staged):
            (root / 'bin').mkdir(parents=True, exist_ok=True)
            (root / 'static/crypta-ui').mkdir(parents=True, exist_ok=True)
            (root / 'bin' / launcher).write_text('#!/usr/bin/env sh\nexit 0\n', encoding='utf-8')
            permission_items = ''.join((f'<li><code>{permission}</code></li>' for permission in permissions.split(',')))
            if app_id == 'trust-graph':
                extra_ui = '<p>Trust Graph Local RC. Local trust only; it is not global truth, local operator choices, not moderation, not blocking, not routing policy, no legacy WoT, no Freetalk, no Sone, no Freemail, and no network crawling.</p><p>Anchors and imported statements persist through the platform trust graph backend.</p><p>Exchange uses content fetch, insert, and subscription APIs.</p><p>Trust Score Service exposes trust.score through operator-approved app-service grants.</p><h2>Import preview</h2><button>Preview import</button><button>Commit import</button><p>Duplicate issuer and conflict summaries discard raw fetched content.</p><h2>Statement lifecycle</h2><h2>Subscriptions</h2><h2>Audit</h2><p>not global truth</p>'
            elif app_id == 'social-inbox':
                extra_ui = '<h2>Reference app scope</h2><p>This social/mail-like reference app runs outside the daemon.</p><p>It is not full WoT and is not Freetalk, Sone, Freemail, encrypted mail, and does not add a daemon-core message store. It makes no network protocol change.</p><h2>Identity</h2><h2>Compose</h2><h2>Publish outbox</h2><h2>USK social sources</h2><h2>Sources and subscriptions</h2><h2>Threaded inbox</h2><label>All channels</label><input type="search"><button>Reply</button><button>Mark thread read</button><button>Pause source</button><button>Resume source</button><button>Block source</button><button>Unblock source</button><button>Mute author</button><button>Export visible</button><div id="export-summary"></div><button>Refresh all active sources</button><div id="trust-service-status"></div><button>Request trust grant</button><button>Refresh trust</button>'
            else:
                extra_ui = ''
            (root / 'static/index.html').write_text(f'<!doctype html><html lang="en"><head><meta name="viewport" content="width=device-width, initial-scale=1"><title>{display_name}</title><link rel="stylesheet" href="./crypta-ui/crypta-ui-tokens.css"><link rel="stylesheet" href="./crypta-ui/crypta-ui.css"><link rel="stylesheet" href="./app.css"></head><body class="cr-app"><main class="cr-shell"><section class="cr-permission-summary" data-crypta-permission-summary data-beta-permission-rationale><ul>{permission_items}</ul></section><h1>{display_name}</h1>{extra_ui}<section class="cr-card"><h2>Format profile</h2><code>crypta.profile.v1</code><code>crypta.feed.snapshot.v1</code><code>crypta.trust.statement.v1</code><code>crypta.social.message.v1</code><code>crypta.social.outbox.v1</code><code>application/vnd.crypta.profile+json</code><code>application/vnd.crypta.feed+json</code><code>application/vnd.crypta.trust+json</code><code>application/vnd.crypta.social.outbox+json</code></section><section class="cr-card" data-first-party-beta-readiness data-beta-empty-state data-beta-error-state data-beta-retry-action data-beta-recovery-action data-beta-app-data-status data-beta-support-metadata data-beta-diagnostics-redaction data-beta-ui-consistency><h2>Beta readiness</h2><button class="cr-button" type="button" data-beta-retry-action>Retry</button><p>Empty state, bounded error state, retry action, operator recovery, app-data status, support metadata, and redacted-summary-only diagnostics.</p></section><p class="cr-status" role="status" aria-live="polite" data-beta-accessibility-status></p></main><script src="./crypta-platform.js"></script><script src="./app.js"></script></body></html>', encoding='utf-8')
            (root / 'static/app.js').write_text(app_js + '\nconst formatProfileMarker = CryptaPlatform.contentFormats;\n', encoding='utf-8')
            (root / 'static/app.css').write_text('body { color: #111; }\n', encoding='utf-8')
            if app_id == 'feed-reader':
                (root / 'bin/migrate-feed-data.sh').write_text('#!/usr/bin/env sh\ncase "$CRYPTA_APP_MIGRATION_MODE" in dry-run|apply) ;; *) exit 64;; esac\ntest "$CRYPTA_APP_MIGRATION_NAMESPACE" = ui-state || exit 64\ntest "$CRYPTA_APP_MIGRATION_FROM" = 1 || exit 64\ntest "$CRYPTA_APP_MIGRATION_TO" = 2 || exit 64\ntest -n "$CRYPTA_APP_MIGRATION_INPUT" || exit 64\ntest -n "$CRYPTA_APP_MIGRATION_OUTPUT" || exit 64\nprintf \'%s\\n\' \'feed migration schema check complete\'\n', encoding='utf-8')
            if app_id == 'trust-graph':
                (root / 'bin/migrate-preview-data.sh').write_text('#!/usr/bin/env sh\ncase "$CRYPTA_APP_MIGRATION_MODE" in dry-run|apply) ;; *) exit 64;; esac\ntest "$CRYPTA_APP_MIGRATION_NAMESPACE" = ui-state || exit 64\ntest "$CRYPTA_APP_MIGRATION_FROM" = 1 || exit 64\ntest "$CRYPTA_APP_MIGRATION_TO" = 2 || exit 64\ntest -n "$CRYPTA_APP_MIGRATION_INPUT" || exit 64\ntest -n "$CRYPTA_APP_MIGRATION_OUTPUT" || exit 64\nprintf \'%s\\n\' \'preview migration schema check complete\'\n', encoding='utf-8')
            for asset_name in design_system_asset_names():
                shutil.copy(design_dir / asset_name, root / 'static/crypta-ui' / asset_name)
            shutil.copy(sdk, root / 'static/crypta-platform.js')
        is_profile_publisher = app_id == 'profile-publisher'
        is_feed_reader = app_id == 'feed-reader'
        is_social_inbox = app_id == 'social-inbox'
        is_trust_graph = app_id == 'trust-graph'
        api_minimum = '16' if is_social_inbox else '22' if is_trust_graph else '9' if is_feed_reader or is_profile_publisher else '3' if app_id == 'site-publisher' else '1'
        api_maximum = str(FIRST_PARTY_CERTIFIED_MAX_CONTRACT_VERSION)
        experimental_accepted = 'true' if is_profile_publisher or is_social_inbox or is_trust_graph else 'false'
        service_lines: list[str] = []
        migration_lines: list[str] = []
        if is_social_inbox:
            service_lines = ['app.services.requests=trust-score', 'app.service-request.trust-score.provider=trust-graph', 'app.service-request.trust-score.service=trust.score', 'app.service-request.trust-score.scopes=score.read', 'app.service-request.trust-score.contexts=message-author', 'app.service-request.trust-score.purpose=Annotate Social Inbox message authors using the local Trust Graph Local RC score service.', 'app.service-request.trust-score.dependency.kind=optional', 'app.service-request.trust-score.dependency.required=false', 'app.service-request.trust-score.dependency.featureId=trust-score-annotations', 'app.service-request.trust-score.dependency.featureName=Trust score annotations', 'app.service-request.trust-score.dependency.reason=Annotates message authors with a local Trust Graph score when the operator approves the service bundle.', 'app.service-request.trust-score.dependency.degradeBehavior=disable-feature', 'app.service-request.trust-score.dependency.minServiceVersion=1', 'app.service-request.trust-score.dependency.maxServiceVersion=1', 'app.service-request.trust-score.dependency.grantBundle=trust-annotations', 'app.service-request.trust-score.dependency.grantExpiresAfter=PT720H']
            migration_lines = ['app.data.schema.current=1', 'app.data.schema.namespaces=ui-state,social', 'app.data.schema.namespace.ui-state.current=1', 'app.data.schema.namespace.social.current=1']
        elif is_trust_graph:
            service_lines = ['app.services.provides=trust-score', 'app.service.trust-score.id=trust.score', 'app.service.trust-score.name=Trust Score Service', 'app.service.trust-score.version=1', 'app.service.trust-score.kind=platform-adapter', 'app.service.trust-score.adapter=trust-graph.score', 'app.service.trust-score.scopes=score.read', 'app.service.trust-score.contexts=message-author,profile', 'app.service.trust-score.description=Returns a bounded local RC Trust Graph score summary for an app-provided public subject.']
            migration_lines = ['app.data.schema.current=2', 'app.data.schema.namespaces=ui-state', 'app.data.schema.namespace.ui-state.current=2', 'app.data.migrations=ui-state-v1-v2', 'app.data.migration.ui-state-v1-v2.namespace=ui-state', 'app.data.migration.ui-state-v1-v2.from=1', 'app.data.migration.ui-state-v1-v2.to=2', 'app.data.migration.ui-state-v1-v2.command=bin/migrate-preview-data.sh', 'app.data.migration.ui-state-v1-v2.rollbackCompatible=false', 'app.data.migration.ui-state-v1-v2.requiresStopped=true', 'app.data.migration.ui-state-v1-v2.description=Validate Trust Graph Local RC UI state schema v2.']
        elif is_feed_reader:
            migration_lines = ['app.data.schema.current=2', 'app.data.schema.namespaces=ui-state', 'app.data.schema.namespace.ui-state.current=2', 'app.data.migrations=ui-state-v1-v2', 'app.data.migration.ui-state-v1-v2.namespace=ui-state', 'app.data.migration.ui-state-v1-v2.from=1', 'app.data.migration.ui-state-v1-v2.to=2', 'app.data.migration.ui-state-v1-v2.command=bin/migrate-feed-data.sh', 'app.data.migration.ui-state-v1-v2.rollbackCompatible=false', 'app.data.migration.ui-state-v1-v2.requiresStopped=true', 'app.data.migration.ui-state-v1-v2.description=Validate Feed Reader UI state schema v2.']
        elif is_profile_publisher:
            migration_lines = ['app.data.schema.current=1', 'app.data.schema.namespaces=profile-draft', 'app.data.schema.namespace.profile-draft.current=1']
        beta_expectation = FIRST_PARTY_BETA_EXPECTATIONS[app_id]
        beta_lines = ['app.beta.readiness=ready', 'app.beta.qualityLevel=beta', 'app.beta.support.owner=crypta-core', f'app.beta.support.uri={FIRST_PARTY_SUPPORT_URI}', 'app.beta.support.diagnostics=redacted-summary-only', 'app.beta.ui.emptyState=true', 'app.beta.ui.errorState=true', 'app.beta.ui.retryAction=true', 'app.beta.ui.recoveryAction=true', f"app.beta.appData={beta_expectation['appData']}", f"app.beta.backupRestore={beta_expectation['backupRestore']}", f"app.beta.exportSupported={beta_expectation['exportSupported']}", f"app.beta.importSupported={beta_expectation['importSupported']}", f"app.beta.migrationDryRunSupported={beta_expectation['migrationDryRun']}", 'app.beta.accessibility=basic-pass', 'app.beta.uiConsistency=design-system-pass', 'app.beta.diagnostics=redacted-summary-only', *[f'permissions.rationale.{permission.strip()}=Required by the first-party beta readiness fixture.' for permission in permissions.split(',') if permission.strip()]]
        manifest_text = '\n'.join(['manifest.version=1', f'app.id={app_id}', f'app.name={display_name}', 'app.version=0.1.0', f'api.minimumVersion={api_minimum}', f'api.maximumTestedVersion={api_maximum}', f"api.targetStability={('experimental' if experimental_accepted == 'true' else 'stable')}", f'api.experimentalCapabilitiesAccepted={experimental_accepted}', f'app.exec=bin/{launcher}', 'app.ui.mode=static', 'app.ui.entry=static/index.html', f'app.permissions={permissions}', *beta_lines, *service_lines, *migration_lines, 'quota.data.bytes=0', 'quota.cache.bytes=0']) + '\n'
        (staged / 'cryptad-app.properties').write_text(manifest_text, encoding='utf-8')
        (source / 'cryptad-app.properties.template').write_text(manifest_text.replace('app.version=0.1.0', 'app.version=${appVersion}'), encoding='utf-8')
        if app_id == 'site-publisher':
            (workspace / 'apps/site-publisher/README.md').write_text('Site Publisher is the first content reference app. Identity-backed publishing is future work.\n', encoding='utf-8')
        if app_id == 'profile-publisher':
            (workspace / 'apps/profile-publisher/README.md').write_text('Profile Publisher creates an app-owned identity, calls the profile-document route, persists bounded app-data draft state in AppVault-safe form, and inserts the signed app-document without storing raw signatures in release evidence. App-data backup scope includes profile drafts and publish summaries. Backups exclude vault private identity material and app-service tokens.\n', encoding='utf-8')
        if app_id == 'feed-reader':
            (workspace / 'apps/feed-reader/README.md').write_text('Feed Reader uses POST /api/v1/content/fetch through SDK feed helpers, uses durable content.subscribe metadata for USK subscriptions, uses app-data for bounded local reader state, then publishes generated feed summaries without storing raw feed bodies. App-data backup scope includes feed sources, selected subscriptions, read state, and safe drafts. Backups exclude vault private identity material and app-service tokens.\n', encoding='utf-8')
        if app_id == 'social-inbox':
            (workspace / 'apps/social-inbox/README.md').write_text('Social Inbox RC is a social/mail-like reference app outside daemon core. It uses AppVault identities, profile-document metadata, bounded crypta.social.message.v1 domain-separated signing, generated app-document outbox publication, content.subscribe USK source metadata, durable app-data records, additive schema-1 beta records without mandatory local migration, local message threads, bounded local search, channel filters, read state, and Trust Graph Local RC annotations only. It supports local-only mute/block filters, source pause/resume state, and redacted message export summaries. It is not a production social network, mail protocol, full WoT implementation, Freetalk/Sone/Freemail compatibility layer, not encrypted mail, daemon-core message store, or a network protocol change, and it avoids private insert URIs, browser-session tokens, raw fetched documents, and private identity material. App-data backup scope includes sources, summaries, drafts, and read state. Release evidence includes reference-app.social-inbox-rc-threading and app-platform.trust-social-beta-hardening. Backups exclude vault private identity material and app-service tokens.\n', encoding='utf-8')
        if app_id == 'trust-graph':
            (workspace / 'apps/trust-graph/README.md').write_text('Trust Graph Local RC creates an app-owned trust identity, signs a trust-statement through AppVault, stores UI-local app-data draft summaries, imports local anchors, and is local trust only, not global truth, moderation, blocking, routing policy, or legacy WoT. App-data backup scope includes UI-local drafts, filters, and redacted import summaries. Backups exclude vault private identity material and app-service tokens.\n', encoding='utf-8')
    for app_id, expectation in FIRST_PARTY_BETA_EXPECTATIONS.items():
        readme_path = workspace / f'apps/{app_id}/README.md'
        readme_path.parent.mkdir(parents=True, exist_ok=True)
        existing_readme = read_source(readme_path)
        readme_path.write_text(existing_readme + f"\n## Beta readiness\nCurrent beta support level: ready for beta operators under the first-party maintenance policy.\nEmpty/error/retry states: staged static UI declares empty states, bounded error states, retry actions, and operator recovery actions.\nApp-data backup/export/import status: app data is {expectation['appData']}; backup/restore is {expectation['backupRestore']}; export is {expectation['exportSupported']}; import is {expectation['importSupported']}.\nMigration dry-run status: {expectation['migrationDryRun']}.\nPermission rationale summary: every requested Platform API permission has a manifest rationale and visible permission disclosure.\nSupport/recovery path: use the first-party app support URI and the operator RC recovery workflow.\nDiagnostic redaction promise: diagnostics are redacted-summary-only and exclude private insert URIs, tokens, raw content, raw app data, local paths, and vault private identity material.\nKnown limitations: beta readiness does not convert Local RC apps into global truth systems or legacy protocol compatibility layers.\n", encoding='utf-8')
    adversarial_markup_test_text = '\n'.join(PUBLIC_BETA_SECURITY_MARKUP_FIXTURES)
    feed_test_dir = workspace / 'apps/feed-reader/src/test/java/network/crypta/apps/feedreader'
    feed_test_dir.mkdir(parents=True, exist_ok=True)
    (feed_test_dir / 'FeedReaderBundleStagingTest.java').write_text('class FeedReaderBundleStagingTest { String fixtures = ' + repr(adversarial_markup_test_text) + '; String rendering = "textContent innerHTML insertAdjacentHTML"; }\n', encoding='utf-8')
    social_test_dir = workspace / 'apps/social-inbox/src/test/java/network/crypta/apps/socialinbox'
    social_test_dir.mkdir(parents=True, exist_ok=True)
    (social_test_dir / 'SocialInboxBundleStagingTest.java').write_text('class SocialInboxBundleStagingTest { String fixtures = ' + repr(adversarial_markup_test_text) + '; String rendering = "textContent innerHTML insertAdjacentHTML"; void verifyBoundedRefreshAll() { String checks = "Promise.all CryptaPlatform.trust.score indexedDB localFilters mutedAuthors blockedSources Export visible boundedExportSummary maxExportedMessages"; } }\n', encoding='utf-8')
    profile_test_dir = workspace / 'apps/profile-publisher/src/test/java/network/crypta/apps/profilepublisher'
    profile_test_dir.mkdir(parents=True, exist_ok=True)
    (profile_test_dir / 'ProfilePublisherBundleStagingTest.java').write_text('class ProfilePublisherBundleStagingTest { String rendering = "textContent innerHTML insertAdjacentHTML"; }\n', encoding='utf-8')
    content_formats_dir = workspace / 'platform-api/src/main/java/network/crypta/platform/api/contentformats'
    content_formats_dir.mkdir(parents=True, exist_ok=True)
    (content_formats_dir / 'ContentFormatProfile.java').write_text('record ContentFormatProfile(String id, String contentType) {}\n', encoding='utf-8')
    (content_formats_dir / 'ContentFormatVersionPolicy.java').write_text('final class ContentFormatVersionPolicy { static final String CONSERVATIVE_V1 = "reject_unknown_fields"; }\n', encoding='utf-8')
    (content_formats_dir / 'ContentFormatProfileRegistry.java').write_text('final class ContentFormatProfileRegistry { static final String PROFILE_DOCUMENT_ID = "crypta.profile.v1"; static final String FEED_SNAPSHOT_ID = "crypta.feed.snapshot.v1"; static final String TRUST_STATEMENT_ID = "crypta.trust.statement.v1"; static final String SOCIAL_MESSAGE_ID = "crypta.social.message.v1"; static final String SOCIAL_OUTBOX_ID = "crypta.social.outbox.v1"; static final String PROFILE_DOCUMENT_CONTENT_TYPE = "application/vnd.crypta.profile+json"; static final String FEED_SNAPSHOT_CONTENT_TYPE = "application/vnd.crypta.feed+json"; static final String TRUST_STATEMENT_CONTENT_TYPE = "application/vnd.crypta.trust+json"; static final String SOCIAL_OUTBOX_CONTENT_TYPE = "application/vnd.crypta.social.outbox+json"; static final int FETCHED_DOCUMENT_MAX_BYTES = 262144; static final int DEFAULT_SIGNED_PAYLOAD_MAX_BYTES = 32768; static final ContentFormatProfile PROFILE_DOCUMENT = new ContentFormatProfile(PROFILE_DOCUMENT_ID, PROFILE_DOCUMENT_CONTENT_TYPE); static final ContentFormatProfile FEED_SNAPSHOT = new ContentFormatProfile(FEED_SNAPSHOT_ID, FEED_SNAPSHOT_CONTENT_TYPE); static final ContentFormatProfile TRUST_STATEMENT = new ContentFormatProfile(TRUST_STATEMENT_ID, TRUST_STATEMENT_CONTENT_TYPE); static final ContentFormatProfile SOCIAL_MESSAGE = new ContentFormatProfile(SOCIAL_MESSAGE_ID, "application/json"); static final ContentFormatProfile SOCIAL_OUTBOX = new ContentFormatProfile(SOCIAL_OUTBOX_ID, SOCIAL_OUTBOX_CONTENT_TYPE); String policy = ContentFormatVersionPolicy.CONSERVATIVE_V1; }\n', encoding='utf-8')
    appvault_dir = workspace / 'platform-api/src/main/java/network/crypta/platform/api/appvault'
    appvault_dir.mkdir(parents=True, exist_ok=True)
    for filename, marker in (('ProfileDocumentRequest.java', 'PROFILE_DOCUMENT_ID PROFILE_DOCUMENT_SIGNING_PURPOSE'), ('SocialMessageRequest.java', 'SOCIAL_MESSAGE_ID DEFAULT_SIGNED_PAYLOAD_MAX_BYTES'), ('TrustStatementRequest.java', 'TRUST_STATEMENT_ID DEFAULT_SIGNED_PAYLOAD_MAX_BYTES')):
        (appvault_dir / filename).write_text(f'''import network.crypta.platform.api.contentformats.ContentFormatProfileRegistry; class {filename.removesuffix('.java')} {{ String marker = "{marker}"; }}\n''', encoding='utf-8')
    queue_dir = workspace / 'platform-api/src/main/java/network/crypta/platform/api/queue'
    queue_dir.mkdir(parents=True, exist_ok=True)
    (queue_dir / 'QueueApiHandler.java').write_text('import network.crypta.platform.api.contentformats.ContentFormatProfileRegistry; class QueueApiHandler { int max = ContentFormatProfileRegistry.DEFAULT_SIGNED_PAYLOAD_MAX_BYTES; }\n', encoding='utf-8')
    content_dir = workspace / 'platform-api/src/main/java/network/crypta/platform/api/content'
    content_dir.mkdir(parents=True, exist_ok=True)
    (content_dir / 'ContentFetchPolicy.java').write_text('import network.crypta.platform.api.contentformats.ContentFormatProfileRegistry; class ContentFetchPolicy { long max = ContentFormatProfileRegistry.FETCHED_DOCUMENT_MAX_BYTES; }\n', encoding='utf-8')
    trustgraph_dir = workspace / 'platform-trustgraph/src/main/java/network/crypta/platform/trustgraph'
    trustgraph_dir.mkdir(parents=True, exist_ok=True)
    (trustgraph_dir / 'TrustDocumentTypes.java').write_text('final class TrustDocumentTypes { static final String TRUST_STATEMENT_V1 = "crypta.trust.statement.v1"; static final String TRUST_STATEMENT_CONTENT_TYPE = "application/vnd.crypta.trust+json"; static final String TRUST_STATEMENT_FILENAME = "trust.json"; }\n', encoding='utf-8')
    (trustgraph_dir / 'TrustStatementCanonicalizer.java').write_text('final class TrustStatementCanonicalizer { byte[] canonicalPayloadBytes() { return (TrustDocumentTypes.TRUST_STATEMENT_V1 + "\\n{}").getBytes(); } }\n', encoding='utf-8')
    content_format_test_dir = workspace / 'platform-api/src/test/java/network/crypta/platform/api/contentformats'
    content_format_test_dir.mkdir(parents=True, exist_ok=True)
    (content_format_test_dir / 'ContentFormatProfileRegistryTest.java').write_text('class ContentFormatProfileRegistryTest { String drift = "TrustDocumentTypes.TRUST_STATEMENT_V1 TrustDocumentTypes.TRUST_STATEMENT_CONTENT_TYPE oversized_document unsupported_version deprecated_version Feed snapshot document is too large"; void redaction() { assertFalse(deprecatedResult.toString().contains("signatureBase64")); } }\n', encoding='utf-8')
    appvault_test_dir = workspace / 'platform-api/src/test/java/network/crypta/platform/api/appvault'
    appvault_test_dir.mkdir(parents=True, exist_ok=True)
    for filename, text in (('ProfileDocumentRequestTest.java', 'Unknown field raw signature'), ('SocialMessageRequestTest.java', 'signatureBase64 unsupported_version'), ('SignedProfileDocumentBuilderTest.java', 'signatureBase64 raw signature'), ('SignedSocialMessageDocumentBuilderTest.java', 'signatureBase64 raw signature')):
        (appvault_test_dir / filename).write_text(f'class T {{ String t = "{text}"; }}\n', encoding='utf-8')
    trustgraph_test_dir = workspace / 'platform-trustgraph/src/test/java/network/crypta/platform/trustgraph'
    trustgraph_test_dir.mkdir(parents=True, exist_ok=True)
    for filename, text in (('TrustStatementCanonicalizerTest.java', 'TrustStatementCanonicalizer.canonicalPayloadBytes crypta.trust.statement.v1\\n'), ('TrustStatementParserTest.java', 'Unknown field oversized_document unsupported_version'), ('TrustStatementVerifierTest.java', 'PayloadChangesAfterSigning signatureBase64')):
        (trustgraph_test_dir / filename).write_text(f'class T {{ String t = "{text}"; }}\n', encoding='utf-8')
    sdk_test_dir = workspace / 'platform-sdk-js/src/test/java/network/crypta/platform/sdk/js'
    sdk_test_dir.mkdir(parents=True, exist_ok=True)
    (sdk_test_dir / 'CryptaPlatformSdkResourceTest.java').write_text('class CryptaPlatformSdkResourceTest { String t = "contentFormats profileDocument feedSnapshot trustStatement socialMessage socialOutbox"; }\n', encoding='utf-8')
    appcatalog_dir = workspace / 'platform-appcatalog/src/main/java/network/crypta/platform/appcatalog'
    appcatalog_dir.mkdir(parents=True, exist_ok=True)
    (appcatalog_dir / 'AppReviewTransparencyRecord.java').write_text('record AppReviewTransparencyRecord(String reviewerKeyId, String latestHash) { String privacy = "record counts latest hashes no raw public key bytes no raw receipt signatures no local paths"; }\n', encoding='utf-8')
    (appcatalog_dir / 'FileAppReviewTransparencyStore.java').write_text('final class FileAppReviewTransparencyStore { String reviewTransparencyLog = "local transparency log"; }\n', encoding='utf-8')
    (appcatalog_dir / 'AppReviewTransparencyLog.java').write_text('final class AppReviewTransparencyLog { String latestHash; String recordCount; }\n', encoding='utf-8')
    (appcatalog_dir / 'AppReviewReceipt.java').write_text('record AppReviewReceipt() { String fingerprintSha256() { return "a"; } String payloadSha256() { return "b"; } String s = "canonicalPayloadBytes AppReviewTrustStatus.ARTIFACT_MISMATCH AppReviewTrustStatus.APP_MISMATCH"; }\n', encoding='utf-8')
    (appcatalog_dir / 'AppReviewReceiptPayload.java').write_text('record AppReviewReceiptPayload() { byte[] canonicalPayloadBytes() { return new byte[0]; } String s = "binding.appId() binding.version() binding.artifactSha256() binding.artifactSizeBytes() review.receipt.decision.reason.sha256 decisionReasonSha256 RECEIPT_VERSION_WITH_DECISION_REASON = 2"; }\n', encoding='utf-8')
    (appcatalog_dir / 'AppReviewReceiptIO.java').write_text('final class AppReviewReceiptIO { String s = "parseProperties appendReceiptProperties review.receipt.signature.value.base64"; }\n', encoding='utf-8')
    (appcatalog_dir / 'AppReviewReceiptVerifier.java').write_text('final class AppReviewReceiptVerifier { String s = "Signature.getInstance(receipt.signature().algorithm()) receipt.payload().canonicalPayloadBytes() receipt.mismatchStatus( binding.appId() binding.version() binding.artifactSha256() binding.artifactSizeBytes() AppReviewTrustStatus.EXPIRED AppReviewTrustStatus.UNKNOWN_REVIEWER AppReviewTrustStatus.REVOKED_RECEIPT REVOKED_REVIEWER RETIRED_REVIEWER REVIEWER_NOT_YET_VALID REVIEWER_EXPIRED REVIEW_POLICY_MISMATCH findReceiptRevocation(receipt) false"; }\n', encoding='utf-8')
    (appcatalog_dir / 'AppReviewTrustStatus.java').write_text('enum AppReviewTrustStatus { REVOKED_RECEIPT("revoked_receipt"), REVOKED_REVIEWER("revoked_reviewer"); AppReviewTrustStatus(String value) {} }\n', encoding='utf-8')
    (appcatalog_dir / 'AppReviewPolicy.java').write_text('final class AppReviewPolicy { String s = "AppReviewPolicyMode.ADVISORY REVOKED_RECEIPT REVOKED_REVIEWER"; }\n', encoding='utf-8')
    (appcatalog_dir / 'AppReviewPolicyMode.java').write_text('enum AppReviewPolicyMode { ADVISORY, WARN_UNTRUSTED, REQUIRE_TRUSTED_REVIEW, REQUIRE_TRUSTED_REVIEW_FOR_APPLY_WHEN_STOPPED }\n', encoding='utf-8')
    (appcatalog_dir / 'AppReviewTrustDecision.java').write_text('record AppReviewTrustDecision(boolean requiresAcknowledgement, boolean blocksInstall, boolean blocksUpdate, boolean blocksPolicyApply) {}\n', encoding='utf-8')
    (appcatalog_dir / 'TrustedReviewerKeys.java').write_text('final class TrustedReviewerKeys { String s = "trusted.reviewers.version public.key.base64 policy.version valid.from revoked.at duplicate trusted reviewer key id Instant.parse version >= 3 ? readReceiptRevocations(properties) : List.of() review.revocations receiptFingerprintSha256 review.revocation."; int receiptRevocations; }\n', encoding='utf-8')
    (appcatalog_dir / 'TrustedReviewerRegistrySummary.java').write_text('record TrustedReviewerRegistrySummary(int receiptRevocationCount) {}\n', encoding='utf-8')
    (appcatalog_dir / 'TrustedReviewerKeyStatus.java').write_text('enum TrustedReviewerKeyStatus { ACTIVE, RETIRED, REVOKED }\n', encoding='utf-8')
    (appcatalog_dir / 'TrustedReviewerKeyLifecycle.java').write_text('record TrustedReviewerKeyLifecycle() { String s = "valid.from valid.until revoked.at revocation.reason revocation metadata requires status=revoked reviewer valid.until must be after valid.from"; }\n', encoding='utf-8')
    (appcatalog_dir / 'TrustedReviewerPolicyConstraint.java').write_text('record TrustedReviewerPolicyConstraint() {}\n', encoding='utf-8')
    (appcatalog_dir / 'AppSubmissionIntakeStatus.java').write_text('enum AppSubmissionIntakeStatus { SUBMITTED("submitted"), REVIEWER_ASSIGNED("reviewer_assigned"), PRE_REVIEW_RUNNING("pre_review_running"), PRE_REVIEW_PASSED("pre_review_passed"), PRE_REVIEW_FAILED("pre_review_failed"), REVIEWED("reviewed"), CAUTION("caution"), REJECTED("rejected"), RESUBMISSION_REQUESTED("resubmission_requested"), STAGED_TO_BETA_CATALOG("staged_to_beta_catalog"), BETA_INSTALL_SMOKE_PASSED("beta_install_smoke_passed"); }\n', encoding='utf-8')
    (appcatalog_dir / 'AppSubmissionIntakeRecord.java').write_text('record AppSubmissionIntakeRecord(int schemaVersion, String submissionId, String submissionDigest, String resubmissionOf, String reviewerAssignment, String preReviewReportDigest, String catalogCandidate, String transparencyLogDigest, boolean nonProduction, String redactionStatus, String auditEvents) {}\n', encoding='utf-8')
    (appcatalog_dir / 'FileAppSubmissionIntakeStore.java').write_text('final class FileAppSubmissionIntakeStore { String layout = "records/<submission-id>.json submissions/<submission-id>.zip ATOMIC_MOVE safeSubmissionId"; }\n', encoding='utf-8')
    (appcatalog_dir / 'AppSubmissionReviewerAssignment.java').write_text('record AppSubmissionReviewerAssignment(String previousReviewerKeyId, String assignmentReasonDigest) { String docs = "reviewer private key material"; }\n', encoding='utf-8')
    (appcatalog_dir / 'AppSubmissionReviewDecisionRecord.java').write_text('record AppSubmissionReviewDecisionRecord(String reviewReceiptFingerprintSha256, String decisionReasonDigest, String feedbackDigest) { String docs = "reviewed/caution intake decisions require receipt"; }\n', encoding='utf-8')
    (appcatalog_dir / 'AppSubmissionCatalogCandidateRecord.java').write_text('record AppSubmissionCatalogCandidateRecord(String betaCatalogCandidateReference, boolean cautionAllowed, String installSmokeStatus) {}\n', encoding='utf-8')
    appcatalog_test_dir = workspace / 'platform-appcatalog/src/test/java/network/crypta/platform/appcatalog'
    appcatalog_test_dir.mkdir(parents=True, exist_ok=True)
    (appcatalog_test_dir / 'AppReviewReceiptTest.java').write_text('class AppReviewReceiptTest { void evaluate_whenReviewerKeyIsRevoked_expectRevokedReviewer() {} void evaluate_whenRetiredReviewerCoversReviewedAt_expectTrustedHistoricalReview() {} void evaluate_whenRetiredReviewerHasNoValidityEnd_expectRetiredReviewer() {} void evaluate_whenPolicyVersionDoesNotMatchReviewerConstraint_expectPolicyMismatch() {} void trustedReviewerKeysLoad_whenPolicyVersionOmitsPolicyId_expectInvalidCatalogEntry() {} void fingerprintSha256_whenReceiptRoundTrips_expectStableFingerprint() {} void evaluate_whenReceiptFingerprintIsRevoked_expectRevokedReceiptNotTrusted() {} void trustedReviewerKeysLoad_whenV3ReceiptRevocationConfigured_expectParsesRevocation() {} void trustedReviewerKeysLoad_whenV2RegistryContainsReceiptRevocation_expectInvalidCatalogEntry() {} void transparency_whenSummarized_expectNoRawPublicKeyBytesOrPaths() { String s = "raw public key"; } }\n', encoding='utf-8')
    (appcatalog_test_dir / 'AppSubmissionIntakeRecordTest.java').write_text('class AppSubmissionIntakeRecordTest { void recordCatalogCandidate_whenRejected_expectCandidateBlocked() {} void recordCatalogCandidate_whenCautionWithoutAllowance_expectBlocked() {} void recordCatalogCandidate_whenReviewed_expectInstallSmokeStatus() {} void recordPreReview_whenRedactionFails_expectSummaryCarriesFailure() {} void parse_whenResubmissionRecord_expectPriorSubmissionLinked() {} }\n', encoding='utf-8')
    (appcatalog_dir / 'RecommendedAppCatalog.java').write_text('public record RecommendedAppCatalog(String trustedCatalogKeyId) { Object source = AppCatalogSource.parse("crypta:USK@example/cryptad-app-catalog.properties"); }\n', encoding='utf-8')
    (appcatalog_dir / 'RecommendedAppCatalogs.java').write_text('final class RecommendedAppCatalogs { static final String FIRST_PARTY_BETA_CATALOG_ID = "crypta-first-party-beta"; String env = "CRYPTAD_FIRST_PARTY_CATALOG_SOURCE CRYPTAD_FIRST_PARTY_CATALOG_TRUSTED_CATALOG_KEY_ID"; }\n', encoding='utf-8')
    (appcatalog_dir / 'AppCatalogChannel.java').write_text('enum AppCatalogChannel { STABLE("stable"), BETA("beta"), NIGHTLY("nightly"), DEPRECATED("deprecated"); AppCatalogChannel(String value) {} }\n', encoding='utf-8')
    (appcatalog_dir / 'AppCatalogProductionMetadata.java').write_text('record AppCatalogProductionMetadata() { static final String defaults = "AppCatalogChannel.STABLE AppCatalogSupportStatus.SUPPORTED"; boolean deprecatedForAutomaticUpdates(){ return true; } }\n', encoding='utf-8')
    (appcatalog_dir / 'AppCatalog.java').write_text('final class AppCatalog { static final int VERSION_PRODUCTION_CHANNELS = 3; static final int VERSION_SECURITY_POLICY = 4; static final int VERSION_FIRST_PARTY_MAINTENANCE = 5; static final int VERSION_THIRD_PARTY_SUBMISSION_REVIEW = 6; Object securityPolicy; if (securityPolicy.hasCatalogFields() && version < VERSION_SECURITY_POLICY) throw new IllegalArgumentException(); }\n', encoding='utf-8')
    (appcatalog_dir / 'AppCatalogMaintenanceMetadata.java').write_text('record AppCatalogMaintenanceMetadata() { String fields = "maintenance.owner maintenance.ownerUri maintenance.supportLevel maintenance.dataSchemaPolicy maintenance.migrationPolicy maintenance.backupRestore maintenance.securityPolicy maintenance.deprecationPolicy maintenance.supportUri"; }\n', encoding='utf-8')
    (appcatalog_dir / 'AppCatalogParser.java').write_text('final class AppCatalogParser { String fields = "VERSION_PRODUCTION_CHANNELS = 3 VERSION_FIRST_PARTY_MAINTENANCE = 5 maximumCryptaVersion securityAdvisory replacementAppId catalog.securityAdvisories catalog.securityAdvisory. catalog.securityDenylist parseCatalogSecurityPolicy parseSecurityPolicyIds version < AppCatalog.VERSION_SECURITY_POLICY Instant.parse maintenance.owner maintenance.supportLevel maintenance.backupRestore api.targetStability"; }\n', encoding='utf-8')
    (appcatalog_dir / 'AppCatalogWriter.java').write_text('final class AppCatalogWriter { String fields = "VERSION_PRODUCTION_CHANNELS = 3 VERSION_FIRST_PARTY_MAINTENANCE = 5 VERSION_THIRD_PARTY_SUBMISSION_REVIEW = 6 maximumCryptaVersion securityAdvisory replacementAppId appendSecurityPolicy catalog.securityAdvisories catalog.securityAdvisory. catalog.securityDenylist maintenance.owner maintenance.supportLevel maintenance.backupRestore api.targetStability catalog.version 6 is required when submission review metadata is present review.submission.id review.decision.reason.sha256"; }\n', encoding='utf-8')
    (appcatalog_dir / 'AppCatalogEntryDescriptor.java').write_text('record AppCatalogEntryDescriptor() { String fields = "maximumCryptaVersion securityAdvisory replacementAppId maintenance.owner maintenance.supportLevel maintenance.backupRestore"; }\n', encoding='utf-8')
    (appcatalog_dir / 'AppCatalogSecurityAdvisory.java').write_text('record AppCatalogSecurityAdvisory(String id, java.net.URI uri) { }\n', encoding='utf-8')
    (appcatalog_dir / 'AppCatalogSecurityAdvisoryRecord.java').write_text('record AppCatalogSecurityAdvisoryRecord(AppCatalogSecuritySeverity severity, AppCatalogSecurityStatus status, AppCatalogSecurityAction action) { String doc = "bounded single-line safeUninstallGuidance"; }\n', encoding='utf-8')
    (appcatalog_dir / 'AppCatalogVersionDenylistEntry.java').write_text('record AppCatalogVersionDenylistEntry(String appId, String version) { boolean matches(String candidateAppId, String candidateVersion) { return true; } String doc = "bounded single-line reason safeUninstallGuidance"; }\n', encoding='utf-8')
    (appcatalog_dir / 'AppCatalogSecurityPolicy.java').write_text('final class AppCatalogSecurityPolicy { String duplicate = "duplicate catalog security advisory id duplicate catalog security denylist id denylist entry references unknown advisory"; Object decisionForInstalledVersion(String appId, String version) { return AppCatalogSecurityDecisionStatus.DENYLISTED; } String action = "DENYLIST"; }\n', encoding='utf-8')
    (appcatalog_dir / 'AppCatalogSecurityDecision.java').write_text('record AppCatalogSecurityDecision(boolean blocksInstall, boolean blocksUpdate, boolean blocksAutomaticApply, String safeUninstallGuidance, String replacementAppId) { }\n', encoding='utf-8')
    (appcatalog_dir / 'AppCatalogSecurityDecisionStatus.java').write_text('enum AppCatalogSecurityDecisionStatus { OK, INFORMATIONAL, WARNING, BLOCKED, DENYLISTED }\n', encoding='utf-8')
    (appcatalog_dir / 'AppCatalogSecuritySeverity.java').write_text('enum AppCatalogSecuritySeverity { NONE, LOW, MEDIUM, HIGH, CRITICAL }\n', encoding='utf-8')
    (appcatalog_dir / 'AppCatalogSecurityStatus.java').write_text('enum AppCatalogSecurityStatus { DRAFT, DETECTED, ACTIVE, PUBLISHED, SUPERSEDED, RESOLVED, WITHDRAWN, RETRACTED; boolean enforcesAdvisoryAction() { return true; } }\n', encoding='utf-8')
    (appcatalog_dir / 'AppCatalogSecurityAction.java').write_text('enum AppCatalogSecurityAction { INFORM, WARN, BLOCK_INSTALL, BLOCK_UPDATE, DENYLIST }\n', encoding='utf-8')
    (appcatalog_dir / 'AppCatalogSource.java').write_text('final class AppCatalogSource { Object source = CryptaCatalogUri.parse("crypta:USK@example/cryptad-app-catalog.properties"); }\n', encoding='utf-8')
    (appcatalog_dir / 'CryptaCatalogUri.java').write_text('final class CryptaCatalogUri { String s = "crypta:USK@ SIGNATURE_QUERY_PREFIX signatureFetchKeyForResolvedCatalog normalizeResolvedCatalogFetchKey requireCompatibleResolvedKeyKind siblingSignatureKey(resolvedKey)"; }\n', encoding='utf-8')
    (appcatalog_dir / 'AppCatalogFetcher.java').write_text('final class AppCatalogFetcher { String s = "ContentFetchPort signatureFetchKeyForResolvedCatalog(catalogBytes.resolvedUri()) MAX_CATALOG_BYTES MAX_SIGNATURE_BYTES"; }\n', encoding='utf-8')
    for name, text in {'AppCatalogMirror.java': 'record AppCatalogMirror(AppCatalogMirrorId id, AppCatalogSourceRole role) { String m = "AppCatalogMirrorHealth"; }\n', 'AppCatalogMirrorId.java': 'record AppCatalogMirrorId(String value) { static final AppCatalogMirrorId PRIMARY = null; }\n', 'AppCatalogSourceRole.java': 'enum AppCatalogSourceRole { PRIMARY, MIRROR }\n', 'AppCatalogMirrorHealth.java': 'record AppCatalogMirrorHealth() {}\n', 'AppCatalogVerifiedRevision.java': 'record AppCatalogVerifiedRevision(String revisionDigest) {}\n', 'AppCatalogRollbackCandidate.java': 'record AppCatalogRollbackCandidate(AppCatalogVerifiedRevision revision) {}\n', 'AppCatalogKeyRotationStatus.java': 'record AppCatalogKeyRotationStatus(String status) {}\n', 'AppCatalogKeyRotationPlan.java': 'record AppCatalogKeyRotationPlan(String nextKeyId) {}\n'}.items():
        (appcatalog_dir / name).write_text(text, encoding='utf-8')
    (appcatalog_dir / 'AppCatalogArtifactDownloader.java').write_text('final class AppCatalogArtifactDownloader { ContentFetchPort port; void copyCryptaArtifact() { Object key = AppCatalogSidecars.cryptaArtifactFetchKey(null); } }\n', encoding='utf-8')
    (appcatalog_dir / 'AppCatalogManager.java').write_text('final class AppCatalogManager { Object downloader = new AppCatalogArtifactDownloader(contentFetchPort); String s = "AppCatalogVerifier.verify sourceStore.write(catalog, source, fetched CATALOG_ID_MISMATCH recordRefreshFailure previous stored sidecars remain in place keyRotationStatus emergencyRefresh"; Object securityDecision(String catalogId, String appId) { return null; } Object installedSecurityDecision(String appId, String version) { return null; } void verifyInstallPlan(AppCatalogInstallPlan plan) { bundleExtractor.verifyStagedBundle(plan.entry(), plan.stagedBundleDirectory(), trustedKeyProvider.trustedKeys()); } }\n', encoding='utf-8')
    (appcatalog_dir / 'AppCatalogOperations.java').write_text('final class AppCatalogOperations { String s = "refreshEndpoints rollbackCandidates sourceStore.readRevision keyRotationStatus"; }\n', encoding='utf-8')
    (appcatalog_dir / 'AppCatalogRefreshCoordinator.java').write_text('final class AppCatalogRefreshCoordinator { String s = "fetchAndVerifyEndpoint AppCatalogVerifier.verify CATALOG_ID_MISMATCH generatedAtComparison catalogContentDigest"; }\n', encoding='utf-8')
    (appcatalog_dir / 'AppCatalogSourceStore.java').write_text('final class AppCatalogSourceStore { String s = "HISTORY_DIRECTORY_NAME REVISION_RETENTION_COUNT recordRevision listRevisions"; }\n', encoding='utf-8')
    appcatalog_tests = workspace / 'platform-appcatalog/src/test/java/network/crypta/platform/appcatalog'
    appcatalog_tests.mkdir(parents=True, exist_ok=True)
    (appcatalog_tests / 'AppCatalogManagerTest.java').write_text('void entry_whenArtifactUriIsCryptaChk_expectAccepted() {}\nvoid prepareInstallPlan_whenCryptaArtifactUsesContentFetchPort_expectVerifiedPlan() {}\nvoid verifyInstallPlan_whenStagedBundleTampered_expectInvalidAppBundle() {}\nvoid download_whenCryptaRuntimeIsUnavailable_expectArtifactFetchUnavailable() {}\nvoid fetch_whenCryptaCatalogResolvesToUskEdition_expectSignatureFetchedFromResolvedEdition() {}\nvoid fetch_whenCryptaResolvedCatalogHasSchemePrefix_expectSignatureFetchedFromResolvedEdition() {}\nvoid fetch_whenCryptaResolvedCatalogChangesKeyKind_expectInvalidCatalogSource() {}\nvoid fetch_whenCryptaSourceUsesContentFetchPort_expectBoundedRequests() {}\nvoid refresh_whenCryptaFetchFails_expectPreviousVerifiedCatalogPreservedAndMetadataUpdated() {}\nvoid refresh_whenCryptaVerificationFailsAfterResolvedFetch_expectMetadataUsesResolvedUri() {}\nvoid refresh_whenPrimaryFailsAndMirrorIsVerified_expectMirrorFallbackAccepted() {}\nvoid refresh_whenMirrorReturnsOlderVerifiedRevision_expectCurrentCatalogPreserved() {}\nvoid rollback_whenPreviousRevisionIsRetained_expectRevisionReverifiedAndRestored() {}\n', encoding='utf-8')
    (appcatalog_tests / 'AppCatalogSourceStoreTest.java').write_text('void read_whenLegacySingleSourceExists_expectPrimaryOnlyMirrorModel() {}\n', encoding='utf-8')
    (appcatalog_tests / 'AppCatalogParserTest.java').write_text('void parse_whenCatalogHasProductionChannelMetadata_expectMetadataNormalized() {}\nvoid parse_whenVersionTwoCatalogOmitsProductionMetadata_expectStableDefaults() {}\nvoid parse_whenCatalogHasMaintenanceMetadata_expectMetadataNormalized() {}\nvoid parse_whenVersionFourCatalogDeclaresMaintenanceMetadata_expectInvalidCatalogEntry() {}\n', encoding='utf-8')
    (appcatalog_tests / 'AppCatalogWriterTest.java').write_text('void serialize_whenVersionTwoCatalogHasProductionMetadata_expectInvalidCatalogEntry() {}\nvoid serialize_whenVersionFourCatalogHasMaintenanceMetadata_expectInvalidCatalogEntry() {}\n', encoding='utf-8')
    (appcatalog_tests / 'AppCatalogSecurityPolicyTest.java').write_text('void parse_whenCatalogHasSecurityPolicy_expectDecisionDenylisted() {}\nvoid parse_whenSecurityAdvisoryLifecycleIsPublished_expectEntryAdvisoryEnforced() {}\nvoid parse_whenSecurityAdvisoryLifecycleIsNonEnforcing_expectEntryAdvisoryNotApplied() {}\nvoid parse_whenVersionThreeCatalogDeclaresSecurityPolicy_expectInvalidCatalogEntry() {}\nvoid parse_whenSecurityPolicyHasDuplicateAdvisoryId_expectInvalidCatalogEntry() {}\nvoid parse_whenSecurityPolicyDenylistReferencesUnknownAdvisory_expectInvalidCatalogEntry() {}\nvoid serialize_whenCatalogHasSecurityPolicy_expectVersionFourDeterministicOutput() {}\n', encoding='utf-8')
    (appcatalog_tests / 'AppCatalogEntryDescriptorTest.java').write_text('void parse_whenCatalogHasProductionChannelMetadata_expectMetadataNormalized() {}\nvoid parse_whenDescriptorHasMaintenanceMetadata_expectMetadataNormalized() {}\n', encoding='utf-8')
    (appcatalog_tests / 'AppCatalogMetadataTest.java').write_text('void productionMetadata_whenParsed_expectStableBetaNightlyDeprecated() {}\nvoid parse_whenMaintenanceMetadataUsesMixedCase_expectNormalizedEnums() {}\n', encoding='utf-8')
    (appcatalog_tests / 'RecommendedAppCatalogsTest.java').write_text('// first-party beta fixture\n', encoding='utf-8')
    appdist_dir = workspace / 'platform-appdist/src/main/java/network/crypta/platform/appdist'
    appdist_dir.mkdir(parents=True, exist_ok=True)
    (appdist_dir / 'AppDataSchemaContract.java').write_text('public record AppDataSchemaContract(Integer currentSchemaVersion) { String fields = "dataSchemaContract app.data.schema.current"; }\n', encoding='utf-8')
    (appdist_dir / 'AppDataNamespaceSchema.java').write_text('public record AppDataNamespaceSchema(String namespace, int currentSchemaVersion) { static String normalizeNamespace(String namespace) { return namespace; } }\n', encoding='utf-8')
    (appdist_dir / 'AppDataMigrationStep.java').write_text('public record AppDataMigrationStep(String stepId, String namespace, int fromSchemaVersion, int toSchemaVersion) { AppDataMigrationStep { AppDataNamespaceSchema.normalizeNamespace(namespace); if (toSchemaVersion <= fromSchemaVersion) throw new IllegalArgumentException(); } }\n', encoding='utf-8')
    (appdist_dir / 'AppDataMigrationCommand.java').write_text('public record AppDataMigrationCommand(String pathText) { static final Object WINDOWS_DRIVE_PREFIX_PATTERN = null; String error = "must stay under the app root"; }\n', encoding='utf-8')
    (appdist_dir / 'AppBundleManifestParser.java').write_text('final class AppBundleManifestParser { String fields = "app.data.schema.current app.data.migration. dataSchemaContract unsupported app.data manifest property app.data.migrations requires app.data.schema.current or app.data.schema.namespaces app.data migration target exceeds declared schema api.targetStability"; }\n', encoding='utf-8')
    (appdist_dir / 'AppApiCompatibilityMetadata.java').write_text('final class AppApiCompatibilityMetadata { String fields = "api.targetStability"; }\n', encoding='utf-8')
    (appdist_dir / 'AppBundleStructureValidator.java').write_text('final class AppBundleStructureValidator { void validate() { Object p = step.command().path(); Files.isRegularFile(p, NOFOLLOW_LINKS); } }\n', encoding='utf-8')
    appdist_test_dir = workspace / 'platform-appdist/src/test/java/network/crypta/platform/appdist'
    appdist_test_dir.mkdir(parents=True, exist_ok=True)
    (appdist_test_dir / 'AppBundleManifestParserTest.java').write_text('class AppBundleManifestParserTest { void parse_whenAppDataMigrationContractPresent_expectContractParsed() {} void parseContent_whenMigrationDeclaresNoTargetSchema_expectFailure() {} void parseContent_whenGlobalMigrationTargetExceedsSchema_expectFailure() {} void parseContent_whenMigrationCommandEscapesBundle_expectFailure() {} void parseContent_whenMigrationFieldIsUnknown_expectFailure() {} }\n', encoding='utf-8')
    (appdist_test_dir / 'AppBundleStructureValidatorTest.java').write_text('class AppBundleStructureValidatorTest { void validate_whenMigrationCommandIsRegularNonExecutableFile_expectAccepted() {} }\n', encoding='utf-8')
    apphost_manifest_dir = workspace / 'platform-apphost/src/main/java/network/crypta/platform/apphost/manifest'
    apphost_manifest_dir.mkdir(parents=True, exist_ok=True)
    (apphost_manifest_dir / 'AppManifest.java').write_text('record AppManifest(Object dataSchemaContract) {}\n', encoding='utf-8')
    (apphost_manifest_dir / 'AppManifestParser.java').write_text('final class AppManifestParser { String s = "manifest.dataSchemaContract()"; }\n', encoding='utf-8')
    api_dir = workspace / 'platform-api/src/main/java/network/crypta/platform/api'
    catalog_api_dir = api_dir / 'appcatalogs'
    catalog_api_dir.mkdir(parents=True, exist_ok=True)
    (catalog_api_dir / 'AppCatalogsApiHandler.java').write_text('final class AppCatalogsApiHandler { void listRecommendedCatalogs() {} void addRecommended() {} void sourceHealth() {} void addMirror() {} void rollback() {} void keyRotationStatus() {} java.util.Map<String, Object> securityResponseSummary() { return java.util.Map.of("securityResponse", "clear"); } void summarize() { json.put("channel", channel); json.put("supportStatus", supportStatus); json.put("sourceDisplay", redactedCatalogSource(source)); json.put("lastResolvedDisplay", lastResolvedDisplay); json.put("maintenance", summarizeMaintenance(metadata)); json.put("securityAdvisories", securityAdvisories); json.put("defaultEntryChannel", "stable"); json.put("allowedChannels", allowedChannels); } void summarizeMaintenance(Object metadata) {} String e = "recommended_catalog_trusted_key_missing"; }\n', encoding='utf-8')
    (api_dir / 'PlatformApiAppRoutes.java').write_text('final class PlatformApiAppRoutes { void routeRecommendedAppCatalogs() {} void routeRecommendedAppCatalogAddOrApp() {} boolean refresh = "refresh".equals(action); String ops = "operations/health operations/revisions operations/key-rotation emergency-refresh mirrors"; }\n', encoding='utf-8')
    (api_dir / 'PlatformApiContract.java').write_text('final class PlatformApiContract { static final int CURRENT_CONTRACT_VERSION = 24; static final int TRUST_GRAPH_PREVIEW_CONTRACT_VERSION = 7; static final int TRUST_GRAPH_EXCHANGE_CONTRACT_VERSION = 10; static final int TRUST_GRAPH_RC_SCOPE_CONTRACT_VERSION = 15; static final int TRUST_GRAPH_BETA_HARDENING_CONTRACT_VERSION = 22; static final int SOCIAL_MESSAGE_CONTRACT_VERSION = 11; static final int CONTENT_SUBSCRIPTIONS_CONTRACT_VERSION = 8; static final int APP_DATA_STORE_CONTRACT_VERSION = 9; static final int APP_SERVICES_CONTRACT_VERSION = 12; static final int APP_SERVICE_DEPENDENCY_BUNDLES_CONTRACT_VERSION = 16; static final int PRODUCTION_CATALOG_CHANNELS_CONTRACT_VERSION = 13; String list = "/app-catalogs/recommended"; String add = "/app-catalogs/recommended/{catalogId}/add"; String refresh = "/app-catalogs/{catalogId}/refresh"; String mirrors = "/app-catalogs/{catalogId}/mirrors"; String operations = "/app-catalogs/{catalogId}/operations/health"; String listAction = "catalogs.recommended.list"; String addAction = "catalogs.recommended.add"; String profileDocument = "/app-vault/identities/{identityId}/profile-document"; String profileAction = "app-vault.identities.profile-document"; String profileReadCapability = "VAULT_IDENTITIES_READ"; String profileUseCapability = "VAULT_IDENTITIES_USE"; String createIdentity = "/app-vault/identities"; boolean browserSafeCreate = true; String generatedDocument = "/queue/inserts/app-document"; String generatedAction = "queue.inserts.app-document"; String contentCapability = "CONTENT_INSERT_APP_DOCUMENT"; String queueCapability = "QUEUE_WRITE"; String contentFetch = "/content/fetch"; String contentFetchCapability = "CONTENT_FETCH"; String CONTENT_FETCH = "CONTENT_FETCH"; String CONTENT_SUBSCRIBE = "CONTENT_SUBSCRIBE"; String contentSubscribe = "content.subscribe"; String contentSubscriptionSince = "sinceContractVersion = 8"; String subscriptionList = "/content/subscriptions"; String subscriptionRead = "/content/subscriptions/{subscriptionId}"; String subscriptionRefresh = "/content/subscriptions/{subscriptionId}/refresh"; String subscriptionPause = "/content/subscriptions/{subscriptionId}/pause"; String subscriptionResume = "/content/subscriptions/{subscriptionId}/resume"; String subscriptionCreateAction = "content.subscriptions.create"; String subscriptionRefreshAction = "content.subscriptions.refresh"; String subscriptionDeleteAction = "content.subscriptions.delete"; String appDataRead = "app.data.read"; String appDataWrite = "app.data.write"; String appDataStatus = "/app-data/status"; String appDataNamespaces = "/app-data/namespaces"; String appDataNamespace = "/app-data/namespaces/{namespace}"; String appDataSchema = "/app-data/namespaces/{namespace}/schema"; String appDataRecords = "/app-data/records"; String appDataRecord = "/app-data/records/{namespace}/{key}"; String appDataExport = "/app-data/export"; String appDataImport = "/app-data/import"; String trustStatus = "/trust-graph/status"; String trustAnchors = "/trust-graph/anchors"; String trustImport = "/trust-graph/import"; String trustImportPreview = "/trust-graph/import-preview"; String trustImportPreviewUri = "/trust-graph/import-preview-uri"; String trustImportUri = "/trust-graph/import-uri"; String trustAudit = "/trust-graph/audit"; String trustSubjects = "/trust-graph/subjects"; String trustStatements = "/trust-graph/statements"; String trustStatement = "/trust-graph/statements/{fingerprint}"; String trustDeprecate = "/trust-graph/statements/{fingerprint}/deprecate"; String trustRevoke = "/trust-graph/statements/{fingerprint}/revoke"; String trustReactivate = "/trust-graph/statements/{fingerprint}/reactivate"; String trustScore = "/trust-graph/score"; String trustRead = "PlatformApiCapabilities.TRUST_READ"; String trustWrite = "PlatformApiCapabilities.TRUST_WRITE"; String trustFetch = "PlatformApiCapabilities.CONTENT_FETCH"; String trustStatement = "/app-vault/identities/{identityId}/trust-statement"; String trustStatementAction = "app-vault.identities.trust-statement"; String socialMessage = "/app-vault/identities/{identityId}/social-message"; String socialMessageAction = "app-vault.identities.social-message"; String appServices = "/app-services"; String appServicesAudit = "/app-services/audit"; String appServicesDependencies = "/app-services/dependencies"; String appServicesConsumerDependencies = "/app-services/dependencies/consumers/{consumerAppId}"; String appServicesGrantBundles = "/app-services/grant-bundles"; String appServicesGrantBundleApprove = "/app-services/grant-bundles/{bundleId}/approve"; String appServicesGrantBundleReject = "/app-services/grant-bundles/{bundleId}/reject"; String appServicesGrantBundleRenew = "/app-services/grant-bundles/{bundleId}/renew"; String appServicesGrants = "/app-services/grants"; String appServicesApprove = "/app-services/grants/{grantId}/approve"; String appServicesRevoke = "/app-services/grants/{grantId}/revoke"; String appServicesProvider = "/app-services/{providerAppId}/services"; String appServicesDescriptor = "/app-services/{providerAppId}/services/{serviceId}"; String appServicesInvoke = "/app-services/{providerAppId}/services/{serviceId}/invoke"; String appServicesRead = "app.services.read"; String appServicesCall = "app.services.call"; String vaultRead = "PlatformApiCapabilities.VAULT_IDENTITIES_READ"; String vaultUse = "PlatformApiCapabilities.VAULT_IDENTITIES_USE"; }\n', encoding='utf-8')
    (api_dir / 'PlatformApiCapabilities.java').write_text('final class PlatformApiCapabilities { static final String TRUST_READ = "trust.read"; static final String TRUST_WRITE = "trust.write"; static final String CONTENT_FETCH = "content.fetch"; static final String CONTENT_SUBSCRIBE = "content.subscribe"; static final String APP_DATA_READ = "app.data.read"; static final String APP_DATA_WRITE = "app.data.write"; static final String APP_SERVICES_READ = "app.services.read"; static final String APP_SERVICES_CALL = "app.services.call"; }\n', encoding='utf-8')
    networkbudget_dir = api_dir / 'networkbudget'
    networkbudget_dir.mkdir(parents=True, exist_ok=True)
    (networkbudget_dir / 'AppNetworkBudgetConfig.java').write_text('record AppNetworkBudgetConfig() { static final Object DEFAULT = new AppNetworkBudgetConfig(20, 200, 2, 16, 48, 1024, 1, 8, 120, 1024, 1, 8); String props = "cryptad.appNetworkBudget.foregroundContentFetchPerAppPerMinute CRYPTAD_APP_NETWORK_BUDGET_FOREGROUND_CONTENT_FETCH_PER_APP_PER_MINUTE cryptad.appNetworkBudget.subscriptionPollPerAppPerHour CRYPTAD_APP_NETWORK_BUDGET_SUBSCRIPTION_POLL_PER_APP_PER_HOUR cryptad.appNetworkBudget.trustGraphImportPerAppPerHour CRYPTAD_APP_NETWORK_BUDGET_TRUST_GRAPH_IMPORT_PER_APP_PER_HOUR"; void requirePositive() {} static AppNetworkBudgetConfig loadFromSystem() { return new AppNetworkBudgetConfig(); } }\n', encoding='utf-8')
    (networkbudget_dir / 'AppNetworkBudgetOperation.java').write_text('enum AppNetworkBudgetOperation { FOREGROUND_CONTENT_FETCH, SUBSCRIPTION_POLL, SUBSCRIPTION_MANUAL_REFRESH, TRUST_GRAPH_IMPORT, TRUST_GRAPH_IMPORT_URI, CONTENT_FETCH_GLOBAL }\n', encoding='utf-8')
    (networkbudget_dir / 'AppNetworkBudgetScope.java').write_text('final class AppNetworkBudgetScope { static final String GLOBAL = "_cryptad_global"; static final String HOST_OPERATOR = "_cryptad_operator"; String normalize(String appId) { return AppManifest.normalizeAppId(appId); } }\n', encoding='utf-8')
    (networkbudget_dir / 'AppNetworkBudgetService.java').write_text('final class AppNetworkBudgetService { AppNetworkBudgetDecision acquire(String appId, AppNetworkBudgetOperation op) { return null; } String safe = "content_fetch_budget_exhausted content_subscription_budget_exhausted trust_graph_import_budget_exhausted"; }\n', encoding='utf-8')
    (networkbudget_dir / 'AppNetworkBudgetStore.java').write_text('interface AppNetworkBudgetStore {}\n', encoding='utf-8')
    (networkbudget_dir / 'FileAppNetworkBudgetStore.java').write_text('final class FileAppNetworkBudgetStore implements AppNetworkBudgetStore { void write() { AppManifest.normalizeAppId("app"); String move = "ATOMIC_MOVE"; } }\n', encoding='utf-8')
    (networkbudget_dir / 'InMemoryAppNetworkBudgetStore.java').write_text('final class InMemoryAppNetworkBudgetStore implements AppNetworkBudgetStore {}\n', encoding='utf-8')
    for name in ('AppNetworkBudgetDecision', 'AppNetworkBudgetSnapshot', 'AppNetworkBudgetUsage', 'AppNetworkBudgetLease'):
        (networkbudget_dir / f'{name}.java').write_text(f'record {name}(String appId, String operation, String windowStart, String lastDecision, String nextAvailableAt) {{}}\n', encoding='utf-8')
    (api_dir / 'PlatformApiRouter.java').write_text('final class PlatformApiRouter { String a = "/trust-graph/status"; String b = "/trust-graph/anchors"; String c = "/trust-graph/import"; String d = "/trust-graph/subjects"; String e = "/trust-graph/statements"; String f = "/trust-graph/score"; String g = "/trust-graph/import-uri"; Object audit = envelope("audit"); void importUri() {} PlatformApiSharedAppServices checkedAppServices; Object checkedRuntimePorts; Object content = new PlatformApiContentRoutes(checkedRuntimePorts, checkedAppServices.contentSubscriptionService(), checkedAppServices.networkBudgetService()); void routeContentSubscriptionsRequest() { requireAppPrincipalId(request); requireAllCapabilities(ContentSubscriptionService.CAPABILITY_CONTENT_SUBSCRIBE, ContentSubscriptionService.CAPABILITY_CONTENT_FETCH); Object h = new ContentSubscriptionsApiHandler(); String unavailable = "content_subscription_service_unavailable 503"; } PlatformApiAppDataRoutes appDataRoutes; PlatformApiAppServiceRoutes appServiceRoutes; String route = "app-services"; // case "app-services" Object app = appServiceRoutes.route(null, null); }\n', encoding='utf-8')
    (api_dir / 'PlatformApiContentRoutes.java').write_text('final class PlatformApiContentRoutes { Object contentFetchPort; AppNetworkBudgetService networkBudgetService; Object contentApiHandler() { return new ContentApiHandler(contentFetchPort, networkBudgetService); } void fetch(Request request) { contentApiHandler().fetch(request.queryParameters(), optionalAppPrincipalId(request)); } String optionalAppPrincipalId(Object request) { return "social-inbox"; } void routeContentSubscriptionsRequest() { requireAppPrincipalId(request); } }\n', encoding='utf-8')
    (api_dir / 'PlatformApiTrustGraphRoutes.java').write_text('final class PlatformApiTrustGraphRoutes { Object routeNestedResourceAction; String routes = "/trust-graph/import-preview /trust-graph/import-preview-uri statements deprecate revoke reactivate anchors/{fingerprint}/deprecate anchors/{fingerprint}/revoke anchors/{fingerprint}/reactivate"; }\n', encoding='utf-8')
    (api_dir / 'PlatformApiSharedAppServices.java').write_text('record PlatformApiSharedAppServices(TrustGraphApiHandler trustGraphApiHandler, AppServiceCoordinator appServiceCoordinator, AppNetworkBudgetService networkBudgetService) {}\n', encoding='utf-8')
    (api_dir / 'PlatformApiAppServiceRoutes.java').write_text('final class PlatformApiAppServiceRoutes { // Routes local app-service discovery\nObject route(Object segments, Object request) { return service.listServices(); } Object dependencies() { return service.dependencyGraph(null); } Object bundles() { approveBundle(); rejectBundle(); renewBundle(); return null; } void approveBundle() {} void rejectBundle() {} void renewBundle() {} }\n', encoding='utf-8')
    appservices_dir = api_dir / 'appservices'
    appservices_dir.mkdir(parents=True, exist_ok=True)
    (appservices_dir / 'AppServiceDescriptor.java').write_text('public record AppServiceDescriptor(String providerAppId, String serviceId) { String compatibilityFingerprint() { return "fp"; } boolean satisfiesVersionRange(Object range) { return true; } boolean hasUnsupportedScopes(Object scopes) { return false; } boolean supportsContext(String context) { return true; } }\n', encoding='utf-8')
    (appservices_dir / 'AppServiceRequestDescriptor.java').write_text('public record AppServiceRequestDescriptor(String consumerAppId, String serviceId) {}\n', encoding='utf-8')
    (appservices_dir / 'AppServiceDependencyDescriptor.java').write_text('record AppServiceDependencyDescriptor(String featureId) {}\n', encoding='utf-8')
    (appservices_dir / 'AppServiceDependencyKind.java').write_text('enum AppServiceDependencyKind { REQUIRED, OPTIONAL }\n', encoding='utf-8')
    (appservices_dir / 'AppServiceDegradeBehavior.java').write_text('enum AppServiceDegradeBehavior { DISABLE_FEATURE, WARN_ONLY, BLOCK_APP_START, BLOCK_UPDATE }\n', encoding='utf-8')
    (appservices_dir / 'AppServiceVersionRange.java').write_text('record AppServiceVersionRange(String min, String max) {}\n', encoding='utf-8')
    (appservices_dir / 'AppServiceGrantBundle.java').write_text('record AppServiceGrantBundle(String bundleId) { // Bundle docs may mention tokens and local paths while fields stay safe. void toJson(java.util.Map<String,Object> json) { json.put("bundleId", bundleId); } }\n', encoding='utf-8')
    (appservices_dir / 'AppServiceGrantBundleStatus.java').write_text('enum AppServiceGrantBundleStatus { PENDING, APPROVED, REJECTED, EXPIRED, REVALIDATION_REQUIRED }\n', encoding='utf-8')
    (appservices_dir / 'AppServiceManifestParser.java').write_text('final class AppServiceManifestParser { String provides = "app.services.provides"; String requests = "app.service-request."; String dependencyPrefix = "app.service-request." + "alias" + ".dependency."; String min = dependencyPrefix + "minServiceVersion"; String max = dependencyPrefix + "maxServiceVersion"; String duration = dependencyPrefix + "grantExpiresAfter"; String duplicate = "duplicate alias"; String pathError = "Field value must not contain local filesystem paths"; }\n', encoding='utf-8')
    (appservices_dir / 'AppServiceGrant.java').write_text('record AppServiceGrant(String grantId, String consumerAppId, String providerAppId, String serviceId, String scopes, String contexts, String purpose, String approvedAt, String revokedAt, String lastUsedAt, long useCount, String tokenFingerprint, String bundleId, String expiresAt, String renewedAt, String compatibilityFingerprint, String providerServiceVersionAtApproval) { // PR-243 does not issue raw service tokens\nString noRawToken = "fingerprint only"; }\n', encoding='utf-8')
    (appservices_dir / 'AppServiceGrantStatus.java').write_text('enum AppServiceGrantStatus { PENDING, ACTIVE, REVOKED, INACTIVE, EXPIRED, REVALIDATION_REQUIRED; String wire = "revalidation-required"; }\n', encoding='utf-8')
    (appservices_dir / 'AppServiceAuditEvent.java').write_text('record AppServiceAuditEvent(String subjectUriHash) { // omits raw subject URIs, raw tokens, and local paths\n}\n', encoding='utf-8')
    (appservices_dir / 'AppServiceGrantStore.java').write_text('interface AppServiceGrantStore { void listBundles(); void writeBundle(); }\n', encoding='utf-8')
    (appservices_dir / 'FileAppServiceGrantStore.java').write_text('class FileAppServiceGrantStore implements AppServiceGrantStore { String a = "ATOMIC_MOVE"; String b = "grants"; String c = "audit"; String d = "bundles"; public void listBundles(){} public void writeBundle(){} }\n', encoding='utf-8')
    (appservices_dir / 'InMemoryAppServiceGrantStore.java').write_text('class InMemoryAppServiceGrantStore implements AppServiceGrantStore { public void listBundles(){} public void writeBundle(){} }\n', encoding='utf-8')
    (appservices_dir / 'AppServiceCoordinator.java').write_text('class AppServiceCoordinator { void requestGrant(){} void approveGrant(){} void revokeGrant(){} void dependencyGraph(){} void requestBundle(){} void approveBundle(){} void rejectBundle(){} void renewBundle(){} void approveOrRenewBundle(){} void ensureDescriptorSupported(){} boolean isExpired(){ return false; } boolean approvalMetadataStillMatches(){ return false; } static final String SUPPORTED_SERVICE_KIND = "platform-adapter"; static final Object MAX_BUNDLE_GRANT_DURATION = null; Object descriptor = null; Object adapters = null; String fp = "descriptor.compatibilityFingerprint() adapters.containsKey"; String dependencyJson = "dependencyJson providerServiceVersion request bodies"; String a = "App principals cannot approve app-service grants."; String c = "App principals cannot approve app-service grant bundles."; String d = "App principals cannot reject app-service grant bundles."; String e = "App principals cannot renew app-service grant bundles."; String f = "effectiveStatus(grant) == AppServiceGrantStatus.ACTIVE"; String g = "AppServiceGrantStatus.EXPIRED"; String b = "active app-service grant"; }\n', encoding='utf-8')
    (appservices_dir / 'TrustGraphScoreAppServiceAdapter.java').write_text('class TrustGraphScoreAppServiceAdapter { static final String ADAPTER_ID = "trust-graph.score"; // not a proxy; invokes TrustGraphApiHandler#score for score.read only\nvoid invoke(){ trustGraphApiHandler.score(null); json.put("subjectUriHash", "sha256:redacted"); Object redactedScore; String scope = "score.read"; String completeWot = "completeWot"; } }\n', encoding='utf-8')
    api_test_dir = workspace / 'platform-api/src/test/java/network/crypta/platform/api'
    api_test_dir.mkdir(parents=True, exist_ok=True)
    app_vault_test_dir = api_test_dir / 'appvault'
    app_vault_test_dir.mkdir(parents=True, exist_ok=True)
    (app_vault_test_dir / 'SocialMessageRequestTest.java').write_text('class SocialMessageRequestTest { String purpose = "purpose"; String payloadBase64 = "payloadBase64"; String type = "crypta.social.message.v1"; }\n', encoding='utf-8')
    (app_vault_test_dir / 'SignedSocialMessageDocumentBuilderTest.java').write_text('class SignedSocialMessageDocumentBuilderTest { String domainSeparatedPayload; String privateKey; }\n', encoding='utf-8')
    (api_test_dir / 'AppVaultApiRouterTest.java').write_text('class AppVaultApiRouterTest { String route = "social-message"; String domain = "crypta.social.message.v1"; String privateKey; String payloadBase64; String trustHardening = "token=secret unsupported parameter"; }\n', encoding='utf-8')
    (api_test_dir / 'PlatformApiCapabilitiesTest.java').write_text('final class PlatformApiCapabilitiesTest { String a = "trust-graph/import-uri content.fetch"; String b = "trust-graph/audit trust.read"; String c = "social-message vault.identities.use"; }\n', encoding='utf-8')
    appservices_test_dir = api_test_dir / 'appservices'
    appservices_test_dir.mkdir(parents=True, exist_ok=True)
    (appservices_test_dir / 'AppServiceManifestParserTest.java').write_text('class AppServiceManifestParserTest { void parseProvidedServices_whenManifestDeclaresTrustScore_expectDescriptor() {} void parseServiceRequests_whenOptionalDependencyFieldsPresent_expectDependencyDescriptor() {} void parseServiceRequests_whenRequiredDependencyFieldsPresent_expectRequiredDescriptor() {} }\n', encoding='utf-8')
    (appservices_test_dir / 'AppServiceGrantStoreTest.java').write_text('class AppServiceGrantStoreTest { void fileStore_whenGrantsReload_expectDeterministicOrderingAndRedactedJson() {} void fileStore_whenBundleAndGrantLifecycleFieldsReload_expectDeterministicRecords() {} void fileStore_whenAuditEventsReload_expectNewestFirstAndRedactedSubjectHash() {} }\n', encoding='utf-8')
    (appservices_test_dir / 'AppServiceCoordinatorTest.java').write_text('class AppServiceCoordinatorTest { void grantLifecycle_whenApprovedThenRevoked_expectInvocationBoundary() {} void invoke_whenConsumerManifestDropsCallPermission_expectDenied() {} void requestGrant_whenProviderNotInstalled_expectProviderMissing() {} void dependencyGraph_whenProviderAvailable_expectSocialInboxTrustGraphEdge() {} void dependencyGraph_whenAppReadsOtherConsumer_expectForbidden() {} void grantBundleLifecycle_whenApprovedExpiredAndRenewed_expectInvocationBoundary() {} void approveBundle_whenRejected_expectNoActiveGrantCreated() {} void invoke_whenProviderDescriptorDriftsAfterBundleApproval_expectRevalidationRequired() {} }\n', encoding='utf-8')
    (appservices_test_dir / 'TrustGraphScoreAppServiceAdapterTest.java').write_text('class TrustGraphScoreAppServiceAdapterTest { void invoke_whenScoreRequested_expectRedactedScoreSummary() { String subjectUriHash; } }\n', encoding='utf-8')
    (api_test_dir / 'PlatformApiAppServicesRouterTest.java').write_text('class PlatformApiAppServicesRouterTest { void route_whenAppUsesDiscoveryGrantAndInvocation_expectGrantBoundary() {} void route_whenAppUsesDependencyAndBundleRoutes_expectScopedReviewFlow() {} void route_whenBundleRejectFails_expectConsentRejectionAuditNotRecorded() {} }\n', encoding='utf-8')
    (api_test_dir / 'TrustGraphApiRouterTest.java').write_text('final class TrustGraphApiRouterTest { void route_whenImportUriHasContentFetchCapability() {} void route_whenAuditReadAfterImport() { String summary = "uri:redacted token=secret"; } void route_whenWriterRevokesImportedStatement_expectLifecycleVisibleAndReimportDoesNotErase() {} void route_whenReaderAttemptsLifecycleMutation_expectForbiddenBeforeHandler() {} void route_whenWriterPreviewsDuplicateIssuerImport_expectRedactedConflictSummary() { String summary = "duplicateIssuerCount conflictCount conflictStatus rawContentDiscarded"; } void route_whenDirectImportBudgetExhausted_expectSafeTooManyRequests() { String error = "trust_graph_import_budget_exhausted"; } void route_whenImportUriImportBudgetExhausted_expectNoFetch() {} void route_whenImportUriContentFetchBudgetExhausted_expectNoFetchOrImport() { String error = "content_fetch_budget_exhausted"; } }\n', encoding='utf-8')
    sdk_test_dir = workspace / 'platform-sdk-js/src/test/java/network/crypta/platform/sdk/js'
    sdk_test_dir.mkdir(parents=True, exist_ok=True)
    (sdk_test_dir / 'CryptaPlatformSdkResourceTest.java').write_text('final class CryptaPlatformSdkResourceTest { void classpathResource_whenTrustExchangeHelpersRequested() {} void classpathResource_whenTrustExchangePublishSignsStatement() {} void classpathResource_whenSocialMessageSigned_expectBoundedVaultRoute() { String route = "/social-message"; String recipientFingerprint; } }\n', encoding='utf-8')
    bridge_dir = workspace / 'bridge-http-runtime/src/main/java/network/crypta/clients/http/bridge'
    bridge_dir.mkdir(parents=True, exist_ok=True)
    (bridge_dir / 'CoreHttpShellRuntimeSupport.java').write_text('final class CoreHttpShellRuntimeSupport { void create() { AppNetworkBudgetService appNetworkBudgetService = new AppNetworkBudgetService(new FileAppNetworkBudgetStore(layout.dataDir().resolve("apps").resolve("network-budget")), AppNetworkBudgetConfig.loadFromSystem()); Object handler = new TrustGraphApiHandler(new FileTrustGraphStore(layout.dataDir().resolve("apps").resolve("trust-graph")), appNetworkBudgetService); Object appServices = new AppServiceCoordinator(layout.dataDir().resolve("apps").resolve("app-services"), new TrustGraphScoreAppServiceAdapter(handler)); ContentSubscriptionService contentSubscriptionService() { return contentSubscriptionService; } ContentSubscriptionService createContentSubscriptionService() { return new ContentSubscriptionService(new FileContentSubscriptionStore(layout.dataDir().resolve("apps").resolve("content-subscriptions")), appNetworkBudgetService); } ContentSubscriptionScheduler createContentSubscriptionScheduler() { return new ContentSubscriptionScheduler(contentSubscriptionService); } void start() { contentSubscriptionScheduler.start(); contentSubscriptionScheduler::close; } }\n', encoding='utf-8')
    appdata_api_dir = api_dir / 'appdata'
    appdata_api_dir.mkdir(parents=True, exist_ok=True)
    (api_dir / 'PlatformApiAppDataRoutes.java').write_text('final class PlatformApiAppDataRoutes { String appId = requireAppPrincipalId(request); String route = "app-data"; }\n', encoding='utf-8')
    (appdata_api_dir / 'AppDataService.java').write_text('final class AppDataService { static final String CAPABILITY_APP_DATA_READ = "app.data.read"; static final String CAPABILITY_APP_DATA_WRITE = "app.data.write"; boolean storeUsageOutsideAppDataDir; AppDataBackupRestoreWorkflow backupRestoreWorkflow; Object exportBackup(AppDataBackupOptions options, String sourceCryptaVersion) { return backupRestoreWorkflow.exportBackup(options, sourceCryptaVersion); } Object listStoreAppIds() { return store.listAppIds(); } Object planRestore(byte[] payload, AppDataRestoreMode mode, String appId) { preflightImport(null); preflightReplaceApp(null); return null; } Object restoreBackup(byte[] payload, AppDataRestoreMode mode, String appId) { replaceImportedNamespaces(null); replaceAppData(appId); return null; } void preflightImport(Object payload) {} void preflightReplaceApp(Object payload) {} void replaceImportedNamespaces(Object payload) {} void replaceAppData(String appId) {} void updateSchema(){ String fromSchemaVersion; String toSchemaVersion; } AutoCloseable beginUpdateMigrationWriteBarrier(String appId) { String error = "app_data_migration_in_progress"; rejectIfUpdateMigrationWriteBarrierActive(appId); return null; } AppDataUpdateSnapshot createUpdateSnapshot(String appId) { String e = "app_data_snapshot_too_large"; return null; } void restoreUpdateSnapshot(String appId, AppDataUpdateSnapshot snapshot) {} void discardUpdateSnapshot(AppDataUpdateSnapshot snapshot) {} byte[] advanceUpdateMigrationDryRunPayload(String appId, String namespace, int from, int to, String summary, byte[] payload, Long targetDataQuotaBytes) { ManifestQuotaCheck.targetManifest(targetDataQuotaBytes); return null; } void preflightUpdateMigrationDryRunPayloads(String appId, java.util.Collection<byte[]> payloads, Long targetDataQuotaBytes) { ManifestQuotaCheck.targetManifest(targetDataQuotaBytes); } Object withImportedRecordTotals(Object metadata, java.util.List<Object> records) { int recordCount = records.size(); long totalBytes = records.size(); return metadata.withTotals(recordCount, totalBytes, metadata.updatedAt()); } void importUpdateMigrationPayload(String appId, String namespace, int from, int to, byte[] payload) {} void recordUpdateMigration(String appId, String namespace, int from, int to, String summary) {} String lastMigrationAt; String quota = "quota.data.bytes"; }\n', encoding='utf-8')
    (appdata_api_dir / 'AppDataBackupRestoreWorkflow.java').write_text('final class AppDataBackupRestoreWorkflow { Object exportBackup(AppDataBackupOptions options, String sourceCryptaVersion) { payloadBase64 = ""; return createBackupBundle(options); } Object createBackupBundle(AppDataBackupOptions options) { AppDataBackupOptions.SCOPE_SINGLE_APP.toString(); AppDataBackupOptions.SCOPE_ALL_APPS.toString(); listStoreAppIds(); return null; } Object listStoreAppIds() { return service.listStoreAppIds(); } }\n', encoding='utf-8')
    (appdata_api_dir / 'AppDataStore.java').write_text('interface AppDataStore { java.util.List<String> listAppIds(); }\n', encoding='utf-8')
    (appdata_api_dir / 'AppDataUpdateSnapshot.java').write_text('record AppDataUpdateSnapshot(String appId, Object payload, long sizeBytes) {}\n', encoding='utf-8')
    (appdata_api_dir / 'AppDataExportPayload.java').write_text('final class AppDataExportPayload { String mismatch = "app_data_import_app_mismatch"; }\n', encoding='utf-8')
    (appdata_api_dir / 'FileAppDataStore.java').write_text('final class FileAppDataStore { List<String> listAppIds() { return List.of(); } String hash = "sha256"; String move = "ATOMIC_MOVE"; String current = "current.properties"; String root = ".cryptad-app-data"; String value = "value.bin"; }\n', encoding='utf-8')
    (appdata_api_dir / 'InMemoryAppDataStore.java').write_text('final class InMemoryAppDataStore { List<String> listAppIds() { return List.of(); } }\n', encoding='utf-8')
    (appdata_api_dir / 'AppDataBackupBundle.java').write_text('record AppDataBackupBundle(AppDataBackupManifest manifest, java.util.List<AppDataBackupEntry> apps) { public String toString() { return "AppDataBackupBundle[metadata only]"; } }\n', encoding='utf-8')
    (appdata_api_dir / 'AppDataBackupEntry.java').write_text('record AppDataBackupEntry(String appId, AppDataExportPayload export) { Object json() { return export.toJsonValue(); } public String toString() { return "AppDataBackupEntry[metadata only]"; } }\n', encoding='utf-8')
    (appdata_api_dir / 'AppDataBackupManifest.java').write_text('record AppDataBackupManifest(int backupVersion, String kind, boolean sensitiveUserData) { static final int CURRENT_BACKUP_VERSION = 1; static final String BACKUP_KIND = "crypta-app-data-backup"; static final String ENCRYPTION_MODE_NONE = "none"; static final String ERROR = "unsupported_backup_encryption"; }\n', encoding='utf-8')
    (appdata_api_dir / 'AppDataBackupOptions.java').write_text('record AppDataBackupOptions(String scope, String appId) { static final String SCOPE_SINGLE_APP = "single-app"; static final String SCOPE_ALL_APPS = "all-apps"; }\n', encoding='utf-8')
    (appdata_api_dir / 'AppDataRestoreMode.java').write_text('enum AppDataRestoreMode { MERGE("merge"), REPLACE_NAMESPACE("replaceNamespace"), REPLACE_APP("replaceApp"); AppDataRestoreMode(String wireName) {} }\n', encoding='utf-8')
    (appdata_api_dir / 'AppDataRestorePlan.java').write_text('record AppDataRestorePlan(String status) { // without raw backup values\nObject toJsonValue() { return status; } }\n', encoding='utf-8')
    (appdata_api_dir / 'AppDataRestoreResult.java').write_text('record AppDataRestoreResult(String status) { // without raw backup values\nObject toJsonValue() { return status; } }\n', encoding='utf-8')
    (appdata_api_dir / 'AppDataStoreConfig.java').write_text('record AppDataStoreConfig(int maxRecordBytes, int maxRecordsPerApp, int maxNamespacesPerApp, int maxExportBytes, int maxImportBytes) { String quota = "quota.data.bytes"; }\n', encoding='utf-8')
    (appdata_api_dir / 'AppDataApiHandler.java').write_text('final class AppDataApiHandler { String fromSchemaVersion; String toSchemaVersion; }\n', encoding='utf-8')
    app_vault_api_dir = api_dir / 'appvault'
    app_vault_api_dir.mkdir(parents=True, exist_ok=True)
    (app_vault_api_dir / 'AppVaultApiHandler.java').write_text('final class AppVaultApiHandler { void createAppOwnedIdentity() {} void createProfileDocument() { String route = "profile-document"; } void createTrustStatement() { String route = "trust-statement"; Object request = TrustStatementRequest.fromQuery(null); String type = "TrustDocumentTypes.TRUST_STATEMENT_V1"; } void createSocialMessage() { String route = "social-message"; Object request = SocialMessageRequest.fromQuery(null); String domain = SocialMessageRequest.SIGNING_PURPOSE; Object result = signDomainSeparatedPayload(null); } }\n', encoding='utf-8')
    (app_vault_api_dir / 'TrustStatementRequest.java').write_text('import network.crypta.platform.api.contentformats.ContentFormatProfileRegistry; final class TrustStatementRequest { // not an arbitrary signing API\nObject SUPPORTED_PARAMETERS; String profile = ContentFormatProfileRegistry.TRUST_STATEMENT_ID; byte[] canonicalBytes() { return TrustStatementCanonicalizer.canonicalPayloadBytes(null); } }\n', encoding='utf-8')
    (app_vault_api_dir / 'SocialMessageRequest.java').write_text('import network.crypta.platform.api.contentformats.ContentFormatProfileRegistry; final class SocialMessageRequest { static final int MAX_BODY_LENGTH = 4096; static final int MAX_SUBJECT_LENGTH = 160; static final int MAX_TAG_COUNT = 12; static final int MAX_SIGNED_PAYLOAD_BYTES = ContentFormatProfileRegistry.DEFAULT_SIGNED_PAYLOAD_MAX_BYTES; static final String FORMAT_TEXT_PLAIN = "text/plain"; static final String SIGNING_PURPOSE = ContentFormatProfileRegistry.SOCIAL_MESSAGE_ID; String domainMarker = "crypta.social.message.v1"; Object ALLOWED_PARAMETERS; Object fromQuery(Object query) { return null; } }\n', encoding='utf-8')
    (app_vault_api_dir / 'SignedSocialMessageDocumentBuilder.java').write_text('final class SignedSocialMessageDocumentBuilder { String publicKeyBase64; String signatureBase64; }\n', encoding='utf-8')
    (api_dir / 'PlatformApiVaultRouter.java').write_text('final class PlatformApiVaultRouter { String route = "trust-statement social-message"; }\n', encoding='utf-8')
    trust_api_dir = api_dir / 'trust'
    trust_api_dir.mkdir(parents=True, exist_ok=True)
    (trust_api_dir / 'TrustGraphApiHandler.java').write_text('final class TrustGraphApiHandler { Object store = new InMemoryTrustGraphStore(); Map status() { String service = "trust-graph-local-rc"; String mode = "local-rc"; String scope = "localAnchorsOnly importedStatementsOnly noCrawling noGlobalModeration noBlocking noRoutingDecisions noLegacyWoTCompatibility"; Object lifecycle = statementLifecycleJson(); String anchorLifecycle = "anchorLifecycle"; String max = "maxEvidenceRows"; return null; } Object statementLifecycleJson() { return null; } void deprecateAnchor() {} void revokeAnchor() {} void reactivateAnchor() {} public Map<String, Object> importStatement() { try (var ignored = acquireTrustGraphImportBudgetLease(appId)) { TrustStatementParser.parse("{}"); } return null; } public Map<String, Object> previewImport(ContentFetchPort port) { String route = "/trust-graph/import-preview"; String uriRoute = "/trust-graph/import-preview-uri"; Object preview = TrustGraphImportPreview.preview("{}", store, "crypta:USK@redacted", "source", 1024, null); String summary = "trust_graph_import_budget Manual review recommended rawContentDiscarded"; try (var importReservation = reserveTrustGraphImportBudget(appId)) { commitTrustGraphImportBudget(importReservation); } return null; } public Map<String, Object> importUri(ContentFetchPort port) { try (var importReservation = reserveTrustGraphImportBudget(appId)) { Object handler = new ContentApiHandler(port, networkBudgetService, AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT_URI); commitTrustGraphImportBudget(importReservation); String max = "maxStoredDocumentBytes"; String format = "format"; String event = "TrustGraphAuditEvent sourceUriHash redactedUriSummary redactedRejectedUriSummary"; } return null; } private AppNetworkBudgetReservation reserveTrustGraphImportBudget(Object appId) { networkBudgetService.reserve(appId, AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT); return null; } private void commitTrustGraphImportBudget(AppNetworkBudgetReservation reservation) { reservation.commit(); } private AppNetworkBudgetLease acquireTrustGraphImportBudgetLease(Object appId) { networkBudgetService.acquire(appId, AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT); return null; } Object score = new TrustGraphScorer(null, null); }\n', encoding='utf-8')
    trustgraph_main_dir = workspace / 'platform-trustgraph/src/main/java/network/crypta/platform/trustgraph'
    trustgraph_test_dir = workspace / 'platform-trustgraph/src/test/java/network/crypta/platform/trustgraph'
    trustgraph_main_dir.mkdir(parents=True, exist_ok=True)
    trustgraph_test_dir.mkdir(parents=True, exist_ok=True)
    (trustgraph_main_dir / 'TrustGraphImportPreview.java').write_text('final class TrustGraphImportPreview { static final int MAX_PREVIEW_STATEMENTS = 64; static final int MAX_CANDIDATE_SUMMARIES = 16; static Object preview(String json, Object store, String sourceUri, String sourceLabel, int maxBytes, Object now) { String counters = "candidateStatementCount acceptedCount rejectedCount duplicateCount duplicateIssuerCount conflictCount revokedDeprecatedExpiredCount rawContentDiscarded"; String summary = "issuerSubjectKey duplicateIssuer conflictStatus Manual review recommended raw fetched content private insert URI browser session token absolute local paths raw app data raw signatures"; return null; } }\n', encoding='utf-8')
    (trustgraph_main_dir / 'TrustStatementParser.java').write_text('final class TrustStatementParser { void parse() { rejectUnknown(null, null, null); } }\n', encoding='utf-8')
    (trustgraph_main_dir / 'TrustStatementValidator.java').write_text('final class TrustStatementValidator { static final int MAX_DOCUMENT_BYTES = 65536; void validate(Object expiresAt, Object issuedAt) { requireScore(0); requireConfidence(0); String check = "expiresAt.isAfter(issuedAt) Character.isISOControl"; } }\n', encoding='utf-8')
    (trustgraph_main_dir / 'TrustGraphStoreSanitizer.java').write_text('final class TrustGraphStoreSanitizer { boolean control(char ch) { return Character.isISOControl(ch); } String normalizeSubscriptionId(String value) { return value; } }\n', encoding='utf-8')
    (trustgraph_main_dir / 'TrustStatementLifecycleStatus.java').write_text('enum TrustStatementLifecycleStatus { ACTIVE, DEPRECATED, REVOKED; String text = "operator-local policy"; }\n', encoding='utf-8')
    (trustgraph_main_dir / 'TrustStatementLifecycleRecord.java').write_text('record TrustStatementLifecycleRecord(String statementFingerprint, TrustStatementLifecycleStatus status, String reasonCode, String replacementUri, String actorAppId) { String text = "operator-local policy"; }\n', encoding='utf-8')
    (trustgraph_main_dir / 'TrustGraphStore.java').write_text('interface TrustGraphStore { void updateLifecycle(); Object lifecycle(); record StoredTrustStatement(String sourceUriKind, String subscriptionId, Object lastSeenAt) {} String normalizeSubscriptionId = "normalizeSubscriptionId"; }\n', encoding='utf-8')
    (trustgraph_main_dir / 'InMemoryTrustGraphStore.java').write_text('final class InMemoryTrustGraphStore implements TrustGraphStore { Object lifecycleRecords; int maxLifecycleRecords; void updateLifecycle(){} String sourceUriKind; String subscriptionId; String lastSeenAt; }\n', encoding='utf-8')
    (trustgraph_main_dir / 'TrustGraphEvidence.java').write_text('record TrustGraphEvidence(String lifecycleStatus, Object nonContributingReasons) {}\n', encoding='utf-8')
    (trustgraph_main_dir / 'TrustGraphScore.java').write_text('record TrustGraphScore(boolean evidenceTruncated, int maxEvidenceRows) {}\n', encoding='utf-8')
    (trustgraph_main_dir / 'TrustGraphScorer.java').write_text('final class TrustGraphScorer { static final int MAX_EVIDENCE_ROWS = 25; String reasons = "nonContributingReasons unanchored unverified expired zero-confidence revoked deprecated evidenceTruncated"; }\n', encoding='utf-8')
    (trustgraph_main_dir / 'FileTrustGraphStore.java').write_text('final class FileTrustGraphStore implements TrustGraphStore { String anchors = "anchors"; String statements = "statements"; String audit = "audit"; Object lifecycleRecords; int maxLifecycleRecords; String sourceUriKind; String subscriptionId; String lastSeenAt; void updateLifecycle(){} void writeLifecycleRecord(){} void loadLifecycleRecords(){} void write() { String temp = "createTempFile"; String move = "ATOMIC_MOVE"; force(); } void force() {} }\n', encoding='utf-8')
    (trustgraph_main_dir / 'TrustGraphStoreConfig.java').write_text('record TrustGraphStoreConfig(int maxStatements, int maxAnchors, int maxAuditEntries, int maxStoredDocumentBytes) {}\n', encoding='utf-8')
    (trustgraph_main_dir / 'TrustGraphAuditEvent.java').write_text('record TrustGraphAuditEvent(String sourceUriHash, String sourceSummary, Boolean signatureVerified) {}\n', encoding='utf-8')
    (trustgraph_test_dir / 'FileTrustGraphStoreTest.java').write_text('final class FileTrustGraphStoreTest { void reopen_whenAnchorStored_expectAnchorDurable() {} void reopen_whenVerifiedStatementAndAnchorStored_expectScoreUsesDurableState() {} void reopen_whenStatementRevokedAndReimported_expectLifecycleDurableAndPreserved() {} void importStatement_whenSameDocumentImportedTwice_expectMetadataReplacedWithoutDuplicate() {} void retention_whenCapsExceeded_expectOldestRecordsEvicted() {} void reopen_whenPersistedRecordIsCorrupt_expectRecordIgnoredSafely() {} void auditEvents_whenStoredAndReopened_expectBoundedNewestFirstAndRedacted() {} void auditEvents_whenDuplicateEventsEvicted_expectOnlyOnePersistedDuplicateDeleted() {} }\n', encoding='utf-8')
    (trustgraph_test_dir / 'TrustGraphScorerTest.java').write_text('final class TrustGraphScorerTest { void score_whenAnchoredStatementRevoked_expectLifecycleBlocksContribution() {} void score_whenAnchoredStatementDeprecated_expectLifecycleBlocksContribution() {} String reasons = "nonContributingReasons unanchored unverified expired zero-confidence revoked deprecated evidenceTruncated MAX_EVIDENCE_ROWS"; }\n', encoding='utf-8')
    (trustgraph_test_dir / 'TrustStatementParserTest.java').write_text('final class TrustStatementParserTest { String malicious = "\\\\u0000 \\\\u0085 50.5 token=secret uri:redacted"; String profiles = "Unknown field oversized_document unsupported_version crypta.trust.statement.v1\\n"; }\n', encoding='utf-8')
    queue_api_dir = api_dir / 'queue'
    queue_api_dir.mkdir(parents=True, exist_ok=True)
    (queue_api_dir / 'QueueApiHandler.java').write_text('import network.crypta.platform.api.contentformats.ContentFormatProfileRegistry; final class QueueApiHandler { void createAppGeneratedDocumentInsert() { String route = "app-document"; int max = ContentFormatProfileRegistry.DEFAULT_SIGNED_PAYLOAD_MAX_BYTES; } }\n', encoding='utf-8')
    content_api_dir = api_dir / 'content'
    content_api_dir.mkdir(parents=True, exist_ok=True)
    (content_api_dir / 'ContentFetchPolicy.java').write_text('import network.crypta.platform.api.contentformats.ContentFormatProfileRegistry; final class ContentFetchPolicy { static final long HARD_APP_FETCH_MAX_BYTES = 1048576; static final long HARD_APP_FETCH_TIMEOUT_MILLIS = 60000; static final long DEFAULT_APP_FETCH_MAX_BYTES = ContentFormatProfileRegistry.FETCHED_DOCUMENT_MAX_BYTES; String families = "CHK@ SSK@ USK@ KSK@ crypta:"; boolean unsafe(String uri) { return uri.contains("http://") || uri.contains("https://") || uri.contains("file://"); } }\n', encoding='utf-8')
    (content_api_dir / 'ContentApiHandler.java').write_text('final class ContentApiHandler { void contentFetch() { String route = "content/fetch"; Object policy = ContentFetchPolicy.normalizeForegroundSource(null); Object operation = AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH; AppNetworkBudgetDecision decision = networkBudgetService.acquire(appId, operation); try (AppNetworkBudgetLease ignored = decision.lease()) { contentFetchPort.fetchContent(null); } Object coding = CodingErrorAction.REPORT; String error = "unsupported_content_source unsupported_content_encoding content_fetch_failed"; } }\n', encoding='utf-8')
    content_subscriptions_dir = content_api_dir / 'subscriptions'
    content_subscriptions_dir.mkdir(parents=True, exist_ok=True)
    (content_subscriptions_dir / 'ContentSubscriptionService.java').write_text('final class ContentSubscriptionService { static final String CAPABILITY_CONTENT_SUBSCRIBE = "content.subscribe"; static final String CAPABILITY_CONTENT_FETCH = "content.fetch"; int perAppSubscriptionLimit; int globalSubscriptionLimit; int maxBytes; int timeoutMillis; String contentSha256; int bytes.length; String lastSeenEdition; String lastSeenResolvedUri; int updateCount; // raw fetched content is digested and then discarded. void refresh() { pollSubscription(null, null, AppNetworkBudgetOperation.SUBSCRIPTION_MANUAL_REFRESH); } void schedulerPoll() { pollSubscription(null, null, AppNetworkBudgetOperation.SUBSCRIPTION_POLL); } void pollSubscription(Object s, Object now, Object op) { try (var budgetReservation = reserveBudget("app", op)) { AppNetworkBudgetDecision budgetDecision = budgetReservation.decision(); if (!budgetDecision.allowed()) { Object status = ContentSubscriptionStatus.BUDGET_EXHAUSTED; nextAfterBudgetDenied(now, null, budgetDecision); String msg = budgetDecision.message(); return; } Object running = "write(running)"; AppNetworkBudgetDecision committedBudget = budgetReservation.commit(); if (!committedBudget.allowed()) { nextAfterBudgetDenied(now, null, committedBudget); String msg = committedBudget.message(); return; } contentFetchPort.fetchContent(null); } } AppNetworkBudgetReservation reserveBudget(Object appId, Object operation) { networkBudgetService.reserve(appId, operation); return null; } void contentChanged(){} void failureBackoff(){} void withFailure(){} void nextAfterBudgetDenied(Object n, Object s, Object d){} String error = "content_fetch_failed"; }\n', encoding='utf-8')
    (content_subscriptions_dir / 'ContentSubscriptionStatus.java').write_text('enum ContentSubscriptionStatus { BUDGET_EXHAUSTED("budget_exhausted"); ContentSubscriptionStatus(String value){} }\n', encoding='utf-8')
    (content_subscriptions_dir / 'ContentSubscription.java').write_text('final class ContentSubscription { String contentSha256; String lastSeenEdition; String lastSeenResolvedUri; int updateCount; }\n', encoding='utf-8')
    (content_subscriptions_dir / 'ContentSubscriptionsApiHandler.java').write_text('final class ContentSubscriptionsApiHandler {}\n', encoding='utf-8')
    (content_subscriptions_dir / 'ContentSubscriptionSource.java').write_text('final class ContentSubscriptionSource { String usk = "USK@"; String crypta = "crypta:"; void hasDisallowedScheme(){} void containsWhitespace(){} String error = "unsupported_content_subscription_source"; }\n', encoding='utf-8')
    (content_subscriptions_dir / 'ContentSubscriptionScheduler.java').write_text('public final class ContentSubscriptionScheduler { ContentSubscriptionSchedulerConfig c; ContentSubscriptionPressureGate p; AtomicBoolean running; void tick(Instant now) { running.compareAndSet(false, true); String alreadyRunning = "alreadyRunning"; Object pressure = pressureGate.assess(); if (!pressure.allowed()) { return; } Object result = service.schedulerPoll(null, now); if (result == ContentSubscriptionStatus.BUDGET_EXHAUSTED) { return; } attempted++; } void start(){ scheduleWithFixedDelay(); config.initialDelay().plus(jitter()); } void close(){ shutdownNow(); } int perTickFetchLimit; }\n', encoding='utf-8')
    (content_subscriptions_dir / 'ContentSubscriptionSchedulerConfig.java').write_text('record ContentSubscriptionSchedulerConfig(int perAppSubscriptionLimit, int globalSubscriptionLimit, int perTickFetchLimit, Object minimumPollInterval, Object maximumFailureBackoff) { String env = "CRYPTAD_CONTENT_SUBSCRIPTIONS_SCHEDULER_PER_TICK_FETCH_LIMIT"; }\n', encoding='utf-8')
    (content_subscriptions_dir / 'FileContentSubscriptionStore.java').write_text('public final class FileContentSubscriptionStore { String move = "ATOMIC_MOVE"; // source URIs are never used as file names. String lastErrorCode; }\n', encoding='utf-8')
    (content_subscriptions_dir / 'ContentSubscriptionPressureGate.java').write_text('public final class ContentSubscriptionPressureGate { QueueSupportPort q; RequestQueuePort r; void assess(){ q.isQueueBackendEnabled(); r.isPersistenceDatabaseKilled(); status.stopping(); status.awaitingPassword(); } }\n', encoding='utf-8')
    platform_api_tests = workspace / 'platform-api/src/test/java/network/crypta/platform/api'
    platform_api_tests.mkdir(parents=True, exist_ok=True)
    (platform_api_tests / 'AppVaultProfileDocumentApiTest.java').write_text('void profileDocument_whenAppUsesGrantedIdentity_expectNoPrivateKeyOrRawSignatureEvidence() { String route = "profile-document"; }\n', encoding='utf-8')
    (platform_api_tests / 'QueueGeneratedDocumentInsertApiTest.java').write_text('void appDocument_whenAppGeneratedBodyQueued_expectNoPrivateInsertUriOrRawBodyEvidence() { String route = "app-document"; }\n', encoding='utf-8')
    (platform_api_tests / 'PlatformApiContractVerifierTest.java').write_text('class PlatformApiContractVerifierTest { void compareStableBaseline_whenStableEndpointIdentityChanges_expectSpecificFinding() {} }\n', encoding='utf-8')
    (platform_api_tests / 'ContentFetchApiTest.java').write_text('void contentFetch_whenFeedFetched_expectNoRawFeedBodyOrRequestBodyEvidence() { String route = "content/fetch"; String capability = "content.fetch"; String rejected = "http:// https:// file:// //example.invalid C:\\\\Users SECRET"; }\n', encoding='utf-8')
    (platform_api_tests / 'ContentApiHandlerTest.java').write_text('void fetch_whenBudgetExhausted_expectDeniedBeforeRuntimePort() { String error = "content_fetch_budget_exhausted"; }\n', encoding='utf-8')
    (platform_api_tests / 'PlatformApiContentRouterTest.java').write_text('void route_whenBrowserAppExhaustsFetchBudget_expectTooManyRequestsBeforeRuntimeFetch() { String error = "content_fetch_budget_exhausted"; }\n', encoding='utf-8')
    (platform_api_tests / 'PlatformApiContentSubscriptionsRouterTest.java').write_text('void route_whenAppLacksContentSubscribe_expectForbidden() { String c = "ContentSubscriptionService.CAPABILITY_CONTENT_SUBSCRIBE"; }\nvoid route_whenAppLacksContentFetchForCreate_expectForbidden() { String c = "ContentSubscriptionService.CAPABILITY_CONTENT_FETCH"; }\nvoid route_whenHostOperatorUsesSubscriptionRoute_expectForbiddenByAppScope() { PlatformApiPrincipal.hostOperator(); }\nvoid route_whenAppReadsAnotherAppsSubscription_expectNotFound() {}\n', encoding='utf-8')
    (platform_api_tests / 'PlatformApiAppDataRouterTest.java').write_text('void route_whenAppReadsAnotherAppsRecord_expectNotFound() {}\nvoid route_whenCapabilityMissingOrServiceUnavailable_expectDeniedOr503() {}\n', encoding='utf-8')
    content_subscription_tests = platform_api_tests / 'content/subscriptions'
    content_subscription_tests.mkdir(parents=True, exist_ok=True)
    (content_subscription_tests / 'ContentSubscriptionServiceTest.java').write_text('void create_whenSourceIsUnsupported_expectBadRequest() {}\nvoid refresh_whenContentMetadataChanges_expectDigestEditionAndDedupe() {}\nvoid refresh_whenSubscriptionBudgetExhausted_expectSafeStatusWithoutFetch() {}\nvoid schedulerPoll_whenSubscriptionBudgetExhausted_expectNoFetch() {}\nvoid refresh_whenFetchThrows_expectBudgetLeaseReleasedForNextRefresh() {}\nvoid refresh_whenRunningStateWriteFails_expectBudgetReservedUntilNextRefresh() {}\n', encoding='utf-8')
    (content_subscription_tests / 'ContentSubscriptionSchedulerTest.java').write_text('void tick_whenSubscriptionIsDue_expectOneBoundedFetchAndUpdatedMetadata() {}\nvoid tick_whenQueueBackendUnavailable_expectSafePressureSkip() {}\nvoid tick_whenQueuePressureSkipsPoll_expectBudgetNotConsumed() {}\nvoid tick_whenAlreadyRunning_expectNoOverlappingFetch() { String overlapping = "overlapping"; }\n', encoding='utf-8')
    (content_subscription_tests / 'FileContentSubscriptionStoreTest.java').write_text('void writeAndRead_whenSubscriptionContainsSourceUri_expectPathUsesAppAndSubscriptionIdsOnly() {}\n', encoding='utf-8')
    networkbudget_tests = platform_api_tests / 'networkbudget'
    networkbudget_tests.mkdir(parents=True, exist_ok=True)
    (networkbudget_tests / 'AppNetworkBudgetServiceTest.java').write_text('void acquire_whenPerAppRateLimitReached_expectDeniedUntilWindowReset() {}\nvoid acquire_whenGlobalRateLimitReachedAcrossApps_expectDenied() {}\nvoid acquire_whenLeaseClosedByExceptionPath_expectConcurrencyReleased() {}\nvoid acquire_whenAppIdMatchesFormerGlobalScope_expectGlobalCounterIsSeparate() {}\nvoid acquire_whenHostOperatorScopeUsesTrustBudget_expectOperatorAppBudgetIsSeparate() {}\n', encoding='utf-8')
    (networkbudget_tests / 'FileAppNetworkBudgetStoreTest.java').write_text('void write_whenMetadataPersisted_expectNoRawContentSecretsOrPaths() {}\nvoid write_whenInternalScopePersisted_expectPathSafeNonAppDirectory() {}\n', encoding='utf-8')
    appdata_tests = platform_api_tests / 'appdata'
    appdata_tests.mkdir(parents=True, exist_ok=True)
    (appdata_tests / 'AppDataServiceTest.java').write_text('void putRecord_whenIdentifierContainsTraversal_expectPathFreeValidationError() {}\nvoid exportImport_whenPayloadRoundTrips_expectValuesCopiedAndOtherAppRejected() {}\nvoid createUpdateSnapshot_whenOtherAppHasData_expectSnapshotIsAppScoped() {}\nvoid restoreUpdateSnapshot_whenDataChangedAfterSnapshot_expectOriginalStateRestored() {}\nvoid appFacingWrites_whenUpdateMigrationWriteBarrierActive_expectMigrationInProgressConflict() {}\nvoid updateMigrationImport_whenWriteBarrierActive_expectInternalMigrationWritesAllowed() {}\nvoid advanceUpdateMigrationDryRunPayload_whenTargetManifestRaisesQuota_expectTargetQuotaUsed() {}\nvoid preflightUpdateMigrationDryRunPayloads_whenCombinedOutputExceedsRecordQuota_expectQuotaError() {}\nvoid advanceUpdateMigrationDryRunPayload_whenChainedDryRun_expectNamespaceTotalsMatchRecords() { importedValueBytes(records); }\nvoid exportBackup_whenSingleAppRequested_expectVersionedEnvelopeAndMetadataOnlyToString() {}\nvoid exportBackup_whenAllAppsRequested_expectKnownAppIdsSorted() {}\nvoid restoreBackup_whenReplaceApp_expectTargetAppClearedAndOtherAppsPreserved() {}\nvoid restorePlan_whenBackupContainsRawValues_expectMetadataOnlyPlan() {}\nlong importedValueBytes(java.util.List<Object> records) { return 0L; }\n', encoding='utf-8')
    (appdata_tests / 'FileAppDataStoreTest.java').write_text('void writeRecord_whenUnreferencedGenerationExists_expectCurrentRecordUnaffected() {}\nvoid listAppIds_whenStoreHasKnownAndMalformedDirectories_expectOnlyNormalizedIds() {}\n', encoding='utf-8')
    (platform_api_tests / 'TrustGraphApiTest.java').write_text('void trustGraph_whenQueried_expectNoRawTrustStatementBodiesOrSignatures() { String route = "trust-graph/score"; String capability = "trust.read"; }\n', encoding='utf-8')
    appcatalog_api_tests = workspace / 'platform-api/src/test/java/network/crypta/platform/api/appcatalogs'
    appcatalog_api_tests.mkdir(parents=True, exist_ok=True)
    (appcatalog_api_tests / 'AppCatalogsApiHandlerTest.java').write_text('void listRecommendedCatalogs_whenConfiguredAndTrusted_expectCanAddAndRedactedSource() {}\nvoid listRecommendedCatalogs_whenHttpsSourceHasQuery_expectQueryRedacted() {}\nvoid listRecommendedCatalogs_whenFileSourceConfigured_expectPathRedacted() {}\nvoid health_whenSourcesContainPathsAndTokens_expectOperationsOutputRedacted() { String s = "file:<configured>"; }\nvoid listApps_whenCatalogSecurityDecisionExists_expectRedactedDecisionIncluded() {}\nvoid securityResponseSummary_whenCatalogHasEmergencyPolicy_expectBoundedStatus() {}\nvoid install_whenCatalogSecurityDecisionIsDenylisted_expectStableSecurityError() {}\nvoid install_whenCatalogSecurityDecisionWarnsWithoutAcknowledgement_expectSecurityAckError() {}\n', encoding='utf-8')
    shell = workspace / 'platform-web-shell/src/main/resources/network/crypta/platform/webshell/static/web-shell.js'
    shell.parent.mkdir(parents=True, exist_ok=True)
    shell.write_text('const legacySecurityLevelsPath = normalizeLocalPath(bootstrap.legacySecurityLevelsPath, "/seclevels/");\nconst legacySecurityLevelsFallbackPath = legacySecurityLevelsPath + "?legacyFallback=security-levels";\nfunction registeredAppUiOrigin(app){ return \'http://127.0.0.1:1234\'; }\nfunction safeSameOriginAppUiHref(url, allowIsolatedLaunchParameter){ return \'/apps/demo/\'; }\nfunction normalizeLaunchFallbackHref(value){}\nfunction normalizeIsolatedLaunchHref(value){}\nfunction normalizeIsolatedProbeHref(value, expectedOrigin){}\nconst originPolicy = \'url.username url.password url.search !== "" url.hash !== "" /apps/\';\nfetch(\'/.well-known/cryptad-origin.json\', { credentials: "omit", mode: "cors" });\nfunction renderRecommendedCatalogs(){}\nfunction renderRecommendedCatalogCard(){}\nfunction renderCatalogOperationsNode(){}\nfunction buildCatalogRollbackForm(){}\nfunction catalogSourceDisplay(){}\nconst catalogOperations = \'operations/health operations/revisions operations/key-rotation operations/emergency-refresh\';\nfunction renderSecurityResponseSummary(response){ return \'Production security response Security response Denylisted app versions Support handling\'; }\nfunction securityResponseTone(status){}\nfunction renderSecurityResponseActionLabels(actions){}\nfunction renderSecurityResponseRecordCard(title, records, lineFormatter){}\nfunction securityResponseAdvisoryLine(advisory){}\nfunction securityResponseDenylistLine(denylistEntry){}\nfunction securityResponseCatalogKeyLine(catalogKey){}\nfunction catalogAppChannel(){}\nfunction securityAdvisoryListNode(){}\nfunction catalogMaintenancePolicyNode(){ return \'Maintenance policy\'; }\nfunction catalogMaintenanceDeclared(){}\nconst catalogChannelSelect = \'catalog-channel-select\'; const deprecatedCard = \'is-deprecated-channel\';\nconst path = \'app-catalogs/recommended\';\nconst action = \'addRecommended\';\nfunction appServiceGrantPath(){}\nfunction setSecurityLegacyFallbackStatus(){ return \'Open the legacy security page\'; }\nfunction renderSecurityLegacyFallbackAction(){ return \'Open legacy password and recovery forms\'; }\nsections.security.append(renderSecurityLegacyFallbackAction());\nconst grants = \'App-service grants\'; const approve = \'Approve\'; const revoke = \'Revoke\';\nconst renew = \'Renew bundle\'; function renderAppServiceDependencyGraph(){}\nfunction renderAppServiceBundleCard(){}\napiUrl("app-services"); apiUrl("app-services/grants"); apiUrl("app-services/dependencies"); apiUrl("app-services/grant-bundles"); apiUrl("app-services/audit?limit=12");\n', encoding='utf-8')
    app_ui_dir = workspace / 'platform-app-ui/src/main/java/network/crypta/platform/appui'
    app_ui_test_dir = workspace / 'platform-app-ui/src/test/java/network/crypta/platform/appui'
    app_ui_dir.mkdir(parents=True, exist_ok=True)
    app_ui_test_dir.mkdir(parents=True, exist_ok=True)
    (app_ui_dir / 'AppUiSecurityHeaders.java').write_text('final class AppUiSecurityHeaders { String csp = "default-src \'none\'; script-src style-src connect-src object-src base-uri worker-src frame-src manifest-src"; String headers = "permissions-policy cross-origin-resource-policy nosniff no-referrer"; }\n', encoding='utf-8')
    (app_ui_test_dir / 'AppUiSecurityHeadersTest.java').write_text('class AppUiSecurityHeadersTest { String unsafe = "admin.example 0.0.0.0 127.0.0.1.attacker.example user:pass@ ftp://"; }\n', encoding='utf-8')
    web_shell_bootstrap_dir = workspace / 'platform-web-shell/src/main/java/network/crypta/platform/webshell/bootstrap'
    web_shell_bootstrap_dir.mkdir(parents=True, exist_ok=True)
    (web_shell_bootstrap_dir / 'WebShellBootstrap.java').write_text('record WebShellBootstrap(String legacySecurityLevelsPath, String legacyDiagnosticPath) { void compact(){ requireLegacyLocalPath(legacySecurityLevelsPath, "legacySecurityLevelsPath"); requireLegacyLocalPath(legacyDiagnosticPath, "legacyDiagnosticPath"); } void requireLegacyLocalPath(String value, String label) { uri.getRawQuery(); uri.getRawFragment(); } }\n', encoding='utf-8')
    (web_shell_bootstrap_dir / 'WebShellBootstrapJson.java').write_text('class WebShellBootstrapJson { String security = "legacySecurityLevelsPath"; String diagnostic = "legacyDiagnosticPath"; }\n', encoding='utf-8')
    web_shell_bootstrap_test = workspace / 'platform-web-shell/src/test/java/network/crypta/platform/webshell/WebShellBootstrapTest.java'
    web_shell_bootstrap_test.parent.mkdir(parents=True, exist_ok=True)
    web_shell_bootstrap_test.write_text('class WebShellBootstrapTest { String legacyDiagnosticPath = "legacyDiagnosticPath"; String marker = "legacyFallback=diagnostic-export"; }\n', encoding='utf-8')
    web_shell_test = workspace / 'platform-web-shell/src/test/java/network/crypta/platform/webshell/WebShellResourcesTest.java'
    web_shell_test.parent.mkdir(parents=True, exist_ok=True)
    web_shell_test.write_text('class WebShellResourcesTest { String grants = "App-service grants"; String security = "function renderSecurityResponseSummary(response) Production security response"; String bundles = "grant-bundles Renew bundle renderAppServiceDependencyGraph"; String diagnostic = "legacyFallback=diagnostic-export legacyDiagnosticPath + \\"?legacyFallback=diagnostic-export\\" Open legacy plaintext diagnostic export"; void assertAppUiOriginHardeningMarkersPresent() {} }\n', encoding='utf-8')
    docs = workspace / 'docs'
    docs.mkdir(parents=True, exist_ok=True)
    first_party_docs = "No private keys are shipped. Static app CSP uses default-src 'none'. CSP is a browser mitigation and not a process sandbox. Public-beta certification treats the environment allow-list as a release boundary. Bubblewrap filesystem containment does not enforce CPU, memory, or network isolation. Public-beta release evidence is redacted evidence. Review governance reports record counts, latest hashes, raw receipt signatures exclusions, and catalog scratch paths exclusions. Ecosystem security advisories use signed catalog.version=4 metadata with inform, warn, block_install, block_update, and denylist actions. Exact app-version denylists show vulnerable installed versions with safe uninstall guidance and export app data before delete guidance, but no automatic uninstall, no global moderation, no plugin compatibility restoration, and no network crawler. Review receipt revocation uses receiptFingerprintSha256 and revoked_receipt, while reviewer-key compromise uses status=revoked and revoked_reviewer. Release evidence includes catalog.security-advisories, catalog.version-denylist, app-review.receipt-revocation, app-review.reviewer-key-compromise-flow, app-update.security-denylist-gates, web-shell.security-advisory-trust-warnings, ecosystem-security.advisory-revocation-redaction, and gate ecosystem.security-advisory-revocation. Security response reports exclude raw signatures, raw public keys, private insert URIs, local filesystem paths, raw request bodies, raw fetched content, and app-data backup payloads. Platform API 1.0 stable baseline documents api.targetStability and operator-only exclusions. The local transparency log is not a global public log. queue-manager publisher site-publisher profile-publisher social-inbox feed-reader trust-graph use permissions.rationale entries, Profile Publisher is the identity-profile reference app. Social Inbox RC is a social/mail-like beta reference app outside the daemon core, outside the daemon, and not a generic browser signing API. It uses AppVault identity, bounded crypta.social.message.v1 social message signing, a Signed social message document format with domain-separated signatures, profile-document metadata, generated app-document outbox insert, durable content.subscribe USK sources, local thread reconstruction, channel filters, bounded local search, app-data read state and drafts, additive schema-1 beta records without mandatory local migration, local mute/block filters, redacted message export, and Trust Graph Local RC message-author annotations only that are not a moderation decision. It is not old plugin ABI compatibility, not Freetalk, Sone, Freemail, not encrypted mail, not a full WoT, not a daemon-core message protocol, and not network protocol changes. Feed Reader & Publisher is the content subscription reference app and uses SDK helpers such as CryptaPlatform.feed.fetchSnapshot and CryptaPlatform.content.subscriptions. Trust Graph Local RC is local trust only, not global truth, not a full Web of Trust, not complete WoT, no crawling, no global moderation, not blocking, no routing decisions, and no legacy WebOfTrust, Freetalk, Sone, or Freemail compatibility. It uses trust.read, trust.write, local anchors, durable local backend storage, redacted audit, bounded trust-statement signing, lifecycle states active, deprecated, and revoked, bounded non-contribution reason codes, Trust Score Service, trust.score, operator-approved app-service grants, and read-only app-service score access. Trust anchors are local. It has no old WebOfTrust plugin compatibility. No FNP/FCP/wire protocol changes are involved. api.minimumVersion, changelog.summary, and review receipts. Maintain artifacts as crypta:CHK@artifact and set CRYPTAD_FIRST_PARTY_CATALOG_SOURCE with CRYPTAD_FIRST_PARTY_CATALOG_TRUSTED_KEY_ID and CRYPTAD_FIRST_PARTY_CATALOG_TRUSTED_CATALOG_KEY_ID. Run crypta-app publish-usk --dry-run for the offline plan, then crypta-app publish-usk --live with a private insert URI loaded from env or protected file. The live USK catalog source is crypta:USK@.../cryptad-app-catalog.properties and cryptad-app-catalog.signature is the sibling sidecar at the same USK edition. Signed catalog verification remains mandatory. Catalog refresh records last verified state, and manual remains the default update policy. Catalog operations use a primary source plus mirrors, mirror transport fallback, explicit rollback, key-rotation status, emergency advisory refresh, and catalog.operations-and-mirrors evidence while excluding private insert URI, absolute local path, private keys, tokens, raw catalog content, raw app data, scratch paths, and staged paths. POST /api/v1/app-vault/identities creates browser-safe app-owned identities with vault.identities.create. POST /api/v1/app-vault/identities/{identityId}/profile-document uses vault.identities.read and vault.identities.use for profile document signing. POST /api/v1/queue/inserts/app-document accepts app-generated document content without a local file path and requires content.insert.app-document plus queue.write. POST /api/v1/content/fetch fetches feed content and requires content.fetch. GET and POST /api/v1/content/subscriptions manage durable USK metadata and require content.subscribe; create and refresh also require content.fetch. The network-content.subscription-scheduler records path-free metadata, queue pressure, no queue HTML, and no raw fetched content. It is not a generic crawler and does not support arbitrary HTTP/HTTPS fetches. The durable app-data store exposes GET /api/v1/app-data/status, GET /api/v1/app-data/namespaces, GET and POST /api/v1/app-data/records, GET /api/v1/app-data/export, and POST /api/v1/app-data/import. App data routes are app-scoped. It requires app.data.read and app.data.write, enforces cryptad.appData.maxRecordBytes and quota bounds, is not a filesystem API, is not a generic database, and is not a secret vault. Export and import are bounded, schema migration metadata is recorded, and Redaction rules exclude raw app-data values. App-data backup and restore uses backupVersion 1 with kind crypta-app-data-backup, single-app and all-apps scope, restore modes merge, replaceNamespace, and replaceApp, sensitive user data warnings, encryption.mode = none, vault secrets and private identity material exclusions, support bundles and release evidence redaction, app-data.backup-restore-portability, and operator-beta.app-data-backup-restore. Contract v12 adds GET /api/v1/app-services, app.services.read, app.services.call, operator-approved app-service grants, and mediated trust.score invocation through Trust Score Service grants. Contract v16 adds GET /api/v1/app-services/dependencies, GET and POST /api/v1/app-services/grant-bundles, optional dependency metadata, trust-annotations, Trust score annotations, grant expiry, renewal, and provider revalidation. Contract v13 adds catalog.version=3 production catalog channels: stable, beta, nightly, and deprecated. Stable is the default automatic update channel, beta and nightly require explicit policy, channel_policy_blocked records excluded automation candidates, and deprecated entries expose replacement metadata without bypassing signed catalog verification. Contract v19 catalog.version=5 adds first-party app maintenance metadata with maintenance.owner, maintenance.supportLevel, maintenance.dataSchemaPolicy, maintenance.migrationPolicy, maintenance.backupRestore, maintenance.securityPolicy, maintenance.deprecationPolicy, and app-catalog.first-party-maintenance-policy evidence. PR-275 adds first-party beta readiness metadata, first-party-app.beta-quality-pass evidence, redacted-summary-only diagnostics, empty/error/retry/recovery UI checks, permission rationale checks, app-data backup/export/import status checks, migration dry-run status checks, support metadata checks, and design-system/accessibility markers. Backup/export does not export vault private identity material. Trust Graph Local RC is not global WoT. Social Inbox RC is not legacy Freemail/Freetalk/Sone protocol compatibility. PR-264 adds app-platform.trust-social-beta-hardening for Trust Graph import preview, duplicate issuer conflict summaries, anchor lifecycle, source budgets, Social Inbox source pause/resume, local mute/block, redacted message export, service-grant annotations, additive schema-1 Social Inbox beta data readiness, consent snapshot digest checks, stale approval rejection, backup-before-update, and provider revalidation. PR-276 adds docs/trust-social-content-format-profiles.md and app-platform.trust-social-content-format-profiles for crypta.profile.v1, crypta.feed.snapshot.v1, crypta.trust.statement.v1, crypta.social.message.v1, and crypta.social.outbox.v1. Production beta reports content-format risk without raw content. These content profiles are Crypta app ecosystem profiles. They are not compatibility promises for legacy WoT, Freetalk, Sone, Freemail, or any old plugin ABI/protocol. The content profiles are not Platform API 1.0 stable baseline route guarantees. Content-format risk covers malformed, oversized, unsupported-version, deprecated-version, and signature/canonicalization mismatch handling without raw profile documents, raw fetched content, raw message bodies, raw trust statements, raw signatures, raw app data, private insert URIs, tokens, or absolute local paths in evidence. Contract v14 adds app-update.data-migration-contract for signed app-data schema migration declarations. Contract v15 adds app-platform.trust-graph-rc-scope-and-safety for Trust Graph Local RC scope, lifecycle, source metadata, and score safety. The app-data migration lifecycle runs a dry-run before bundle replacement, creates an internal rollback snapshot, restores app data on failed migration rollback, and keeps rollback snapshot scope app-only. It blocks missing migration paths and rollback-incompatible migrations until operator review, and PR-250 long-term backup/restore portability is handled by the operator backup envelope. It is not generic RPC, not a localhost proxy, and does not give apps ambient access to provider ports or data. It issues no raw service tokens and keeps raw request bodies out of evidence. Social Inbox uses a Trust Score Service grant for message-author annotations; revoked grants fail, and it must not fall back to\n`CryptaPlatform.trust.score`. Release evidence covers app-services.registry, app-services.grants, app-services.dependency-graph, app-services.grant-bundles, app-services.grant-expiry-renewal, app-services.provider-revalidation, app-services.trust-score-provider, reference-app.social-inbox-service-grant, reference-app.social-inbox-service-dependency, app-services.web-shell, app-services.redaction, and app-services.dependency-redaction. Feed Reader and Profile Publisher use app-data for bounded local state. Trust Graph Local RC uses UI-local app-data state separate from the platform trust graph backend. The durable local backend has a durable file-backed preview store that persists local trust anchors, imported public statements, and redacted audit entries. Contract v10 adds POST /api/v1/trust-graph/import-uri and GET /api/v1/trust-graph/audit. Exchange uses content fetch, insert, and subscription APIs and does not crawl the network globally. POST /api/v1/app-vault/identities/{identityId}/trust-statement signs bounded trust statements. POST /api/v1/app-vault/identities/{identityId}/social-message signs bounded social messages with vault.identities.read and vault.identities.use. GET /api/v1/trust-graph/status and GET /api/v1/trust-graph/score read local trust preview data. Release evidence covers reference-app.profile-publisher, reference-app.social-inbox, reference-app.social-inbox-signed-message, reference-app.social-inbox-subscriptions, reference-app.social-inbox-app-data, reference-app.social-inbox-trust-annotations, reference-app.social-inbox-rc-threading, reference-app.social-inbox-service-dependency, migration.social-mail-preview, legacy-plugin.migration-guide, legacy-plugin.social-inbox-spike, legacy-plugin.freeze-policy, legacy-plugin.migration-finalization, legacy-admin.removal-wave-4, reference-app.feed-reader, reference-app.feed-reader-subscriptions, app-platform.content-fetch, app-platform.content-subscriptions, network-content.subscription-scheduler, app-platform.durable-app-data-store, reference-app.feed-reader-app-data, reference-app.profile-publisher-app-data, reference-app.trust-graph-app-data-preview, reference-app.trust-graph, reference-app.trust-graph-durable-exchange, app-platform.trust-graph-preview, app-platform.trust-graph-durable-store, app-platform.trust-graph-exchange, app-platform.trust-social-beta-hardening, app-platform.trust-social-content-format-profiles, app-update.data-migration-contract, catalog.production-channels, app-platform.trust-statement-signing, app-platform.social-message-signing, app-platform.identity-profile-publish, and app-platform.generated-document-insert. Developers can find legacy-plugin-freeze-policy.md, legacy-plugin-migration-guide.md, legacy-plugin-migration-cookbook.md, and plugin-system.md from the app-platform portal. The production RC plugin freeze policy says the old in-process plugin runtime is frozen and removed, with no new in-core plugin APIs, no old plugin ABI compatibility, no old FCP plugin command compatibility, and docs/legacy historical material only. Migration uses out-of-process apps, Platform API, signed catalogs, AppVault, content subscriptions, durable app data, Trust Graph Local RC, and app-service grants. Network-scale soak and subscription budget evidence covers network-scale.app-network-budget, network-scale.content-fetch-budget, network-scale.subscription-budget, network-scale.queue-pressure-backoff, network-scale.trust-graph-import-budget, network-scale.social-inbox-multi-source-soak, and network-scale.redaction. The self-test-network-scale-soak.json fixture represents simulated RC soak evidence; literal 24h live soak is an RC release activity, not a unit test. Foreground content fetches, subscription polling, manual refreshes, and Trust Graph import-uri share relevant global budgets; subscriptions are not a generic crawler. Budget exhaustion returns safe 429/status metadata and queue pressure can delay polls without queue HTML or raw daemon exceptions. Evidence excludes raw fetched content, raw request bodies, queue HTML, browser-session tokens, app process tokens, private insert URIs, raw signatures, raw app-data payloads, and absolute local paths. It excludes raw request bodies, private keys, private key material, raw signatures, private insert URIs, raw source URIs, and absolute staging paths. It also excludes raw feed bodies, raw message bodies, raw fetched content, raw fetched documents, raw trust statement bodies, browser-session tokens, form passwords, and local paths.\n"
    first_party_docs += 'Production security response uses docs/production-security-response-runbook.md and production-security.response-runbook evidence for reviewer key compromise, catalog key rotation, app signing key compromise, emergency catalog update drills, support redaction, and security release notes. Third-party developer beta program docs cover crypta-app init --template hello-stable, crypta-app test, crypta-app ui lint, crypta-app api policy, crypta-app api diff, crypta-app compat verify, crypta-app pack, crypta-app submission create, crypta-app submission verify, crypta-app submission pre-review, crypta-app submission decide, crypta-app submission catalog-candidate, reviewed, caution, rejected, resubmission, resubmitted, api.targetStability=stable, api.experimentalCapabilitiesAccepted=false, platform.contract.read, third-party-app-submission-checklist.md, third-party-developer-beta-program.md, platform-api-compatibility-support-window.md, third-party-developer.beta-program, third-party-developer.docs, third-party-developer.template, third-party-developer.sample-app-flow, third-party-developer.submission-checklist, third-party-developer.compatibility-window, third-party-developer.feedback-workflow, third-party-developer.plugin-author-migration, third-party-developer.redaction, Platform API 1.0 stable baseline, api.experimentalCapabilitiesAccepted=true, scheduled-for-removal, Release certification, previous release-candidate snapshot, Previous Contract Snapshot, experimental-to-stable graduation, stable reference update, platform-api.compatibility-window, platform-api.previous-contract-snapshot, platform-api.deprecation-window-policy, platform-api.experimental-graduation-policy, compatibility waiver policy and non-waiverable stable removal blockers, Catalog candidates and review metadata, private keys, private insert URIs, browser session tokens, raw app data, local absolute paths, and raw fetched content. Public-beta app intake uses crypta-app submission intake import, crypta-app submission intake assign, crypta-app submission intake pre-review, crypta-app submission intake decide, crypta-app submission intake stage-candidate, and crypta-app submission intake install-smoke. Release evidence covers third-party-intake.queue-schema, third-party-intake.import, third-party-intake.reviewer-assignment, third-party-intake.pre-review-artifacts, third-party-intake.review-decision, third-party-intake.resubmission-flow, third-party-intake.catalog-candidate-staging, third-party-intake.beta-catalog-install-smoke, third-party-intake.transparency-export, third-party-intake.rejected-candidate-blocked, third-party-intake.caution-warning, and third-party-intake.redaction. The intake flow marks non-production evidence and keeps redaction failures blocking. '
    for doc_name in ('app-catalogs.md', 'app-review-governance.md', 'app-data-backup-restore-portability.md', 'app-data-store.md', 'app-dev-cli.md', 'app-service-discovery-and-grants.md', 'app-store-submission-and-review-workflow.md', 'app-platform-developer-portal.md', 'app-platform-beta-known-limitations.md', 'app-platform-beta-tutorials.md', 'third-party-developer-beta-program.md', 'third-party-app-submission-checklist.md', 'platform-api-compatibility-support-window.md', 'app-upgrade-data-migrations.md', 'app-permissions-and-audit.md', 'feed-reader-reference-app.md', 'profile-publisher-reference-app.md', 'trust-social-content-format-profiles.md', 'platform-api-contract.md', 'platform-api-1.0-stable-reference.md', 'platform-api-surface.md', 'platform-sdk-js.md', 'production-first-party-catalog-channels.md', 'first-party-app-maintenance-policy.md', 'first-party-app-beta-quality-pass.md', 'ecosystem-security-advisories.md', 'SECURITY.md', 'operator-rc-recovery-and-support-workflow.md', 'production-beta-release-pipeline.md', 'production-beta-go-no-go-dashboard.md', 'cryptad-release-workflow-and-runbook.md', 'social-inbox-reference-app.md', 'trust-graph-preview.md', 'first-party-beta-catalog.md', 'release-certification.md', 'network-scale-soak-and-subscription-budget.md'):
        (docs / doc_name).write_text(first_party_docs, encoding='utf-8')
    (docs / 'third-party-app-submission-checklist.md').write_text('\n'.join(('# Third-party app submission checklist', 'Manifest validation', 'API stability target', 'No internal/operator-only permissions', 'Permission rationale', 'UI lint', 'CSP and remote script policy', 'Sandbox declaration', 'App-data schema declaration', 'Data migration declaration', 'Legacy plugin migration plan using legacy-plugin-migration-cookbook.md', 'Backup/restore declaration', 'Service dependency/grant declaration', 'Security notes', 'Support/maintainer metadata', 'Redaction and privacy review', 'Submission package generation', 'Pre-review output', 'Resubmission requirements')) + '\n', encoding='utf-8')
    examples_dir = docs / 'examples'
    examples_dir.mkdir(parents=True, exist_ok=True)
    (examples_dir / 'third-party-hello-stable.md').write_text('CryptaPlatform.api.get("platform/contract") api.targetStability=stable crypta-app compat verify third-party hello-stable SDK example.\n', encoding='utf-8')
    public_beta_dir = docs / 'public-beta'
    public_beta_dir.mkdir(parents=True, exist_ok=True)
    public_beta_common = '\n'.join(('# Public beta onboarding', 'I am a beta user/operator', 'I am installing or updating Cryptad', 'I am installing first-party apps', 'I am backing up or restoring app data', 'I am troubleshooting a problem', 'I am reporting a security issue', 'I am a third-party app developer', 'I am a former plugin author', 'I am a reviewer/release manager', 'install and start Cryptad', 'open Web Shell', 'stable catalog', 'first-party app', 'permissions', 'rollback', 'app-data backup', 'support bundle', 'Trust Graph Local RC', 'not global WebOfTrust', 'Social Inbox RC', 'not Freemail', 'crypta-app init', 'submission pre-review', 'security reporting', 'legacy plugin migration', 'FProxy browse remains retained'))
    public_beta_doc_text = {'README.md': public_beta_common, 'user-guide.md': '\n'.join(('# Public beta user guide', 'Install and start Cryptad', 'Open Web Shell', 'check node status', 'stable catalog', 'catalog health', 'install a first-party app', 'Review permissions', 'service grants', 'Update or rollback an app', 'Back up or restore app data', 'privacy-preserving support bundle', 'Recover from common failures')), 'install-update-rollback.md': 'daemon update app update production beta artifact verification backup-before-update app-data migration dry-run app rollback catalog rollback safe support bundle\n', 'catalogs-and-apps.md': 'stable beta nightly primary catalog source catalog mirrors transport fallback only catalog signature verification catalog health status catalog rollback catalog key rotation security advisory denylist caution rejected reviewed states\n', 'permissions-and-consent.md': 'capabilities permission rationale permission delta user consent app-service dependency grants optional required grant expiry renewal revocation app-data migration consent security advisory acknowledgement audit events\n', 'trust-social-limitations.md': '\n'.join(('# Public beta trust and social limitations', 'Trust Graph Local RC', 'local advisory trust only', 'not global WebOfTrust', 'not routing policy', 'not global moderation', 'not a crawler', 'not legacy WoT compatibility', 'not a daemon-core identity-sharing system', 'not authority for apps to import or mutate trust data', 'trust.score', 'operator-approved app-service grants', 'Social Inbox RC', 'not Freemail', 'not Freetalk/Sone compatibility', 'not encrypted mail transport', 'not daemon-core social store', 'not a background crawler', 'not a promise that old social plugins will run unchanged')), 'developer-quickstart.md': '\n'.join(('# Public beta developer quickstart', './gradlew :platform-devtools:installDist', 'crypta-app init --dir build/dev-apps/hello-stable --template hello-stable', 'crypta-app dev', 'crypta-app test', 'crypta-app ui lint', 'crypta-app api snapshot', 'crypta-app api policy', 'crypta-app compat verify', 'crypta-app keys generate', '--private-key-file build/dev-keys/dev-local-private.der', '--public-key-file build/dev-keys/dev-local-public.der', '--trusted-keys-file build/dev-keys/trusted-app-keys.properties', 'crypta-app sign', 'crypta-app verify', 'crypta-app pack', 'crypta-app submission create', 'crypta-app submission verify', 'crypta-app submission pre-review', 'submission verify --json')), 'app-submission-walkthrough.md': 'create submission package verify package automated pre-review intake queue reviewer assignment reviewed caution rejected resubmission_requested review receipt transparency log beta catalog candidate install from beta catalog\n', 'troubleshooting.md': '\n'.join(('# Public beta troubleshooting', 'Cannot open Web Shell', 'Catalog not reachable', 'Catalog mirror unhealthy', 'Catalog signature verification failed', 'App install failed', 'App update staged but not applied', 'App rollback needed', 'Permission delta blocks update', 'Grant expired or revoked', 'Subscription stuck', 'App-data migration failed', 'Backup restore failed', 'Sandbox provider unavailable', 'Security advisory blocks update', 'Support bundle export needed')), 'security-reporting.md': '\n'.join(('# Public beta security reporting', 'Report suspected vulnerabilities', 'What not to include', 'Advisories and denylists', 'Support bundle redaction expectations', 'docs/SECURITY.md', 'private insert URIs', 'raw support bundles', 'security-release-notes.md', 'Public bug report', 'Private security report', 'Security advisory or denylist event', 'Reviewer key compromise', 'Catalog signing key compromise', 'App signing key compromise', 'Support bundle redaction failure', 'Do not include exploit details')), 'legacy-plugin-authors.md': 'legacy plugin migration legacy plugin freeze policy migration cookbook FProxy browse remains retained no old plugin ABI compatibility no WebOfTrust Freetalk Sone Freemail compatibility promise\n', 'support-and-feedback.md': '\n'.join(('# Public beta support and feedback loop', 'observe the issue', 'collect a privacy-preserving diagnostic summary', 'export a support bundle locally', 'file the most specific structured issue form', 'Maintainers run the redaction check', 'known issue', 'backlog candidate', 'beta release notes template', 'next beta candidate verifies', 'support_bundle_digest support_bundle_schema_version diagnostic_summary_id', 'consent_audit_event_id operator_recovery_action_id known_issue_id', 'private insert URI private keys browser session tokens raw fetched content', 'raw app data values absolute local paths', 'support bundles are local-only and include digest, schema version, diagnostic summary fields', 'Raw app-data backups are not support bundles', 'reviewed redacted bundle do not attach')), 'triage-taxonomy.md': '\n'.join(app_platform_docs_check.PUBLIC_BETA_TRIAGE_LABELS), 'known-issues.md': '\n'.join(('# Public beta known issues', *app_platform_docs_check.KNOWN_ISSUE_FIELDS, 'PBKI-EXAMPLE-001')), 'feedback-to-backlog.md': '\n'.join(('# Feedback to backlog workflow', 'intake', 'redaction check', 'reproduction check', 'triage category', 'known issue matching', 'support response', 'security escalation', 'developer or app-review escalation', 'release blocker decision', 'backlog candidate creation', 'next beta verification', 'release notes entry', 'closure criteria', 'Catalog cannot refresh', 'App update failed', 'Subscription stuck', 'Trust Graph import warning', 'Social Inbox rendering issue', 'Third-party app compatibility report', 'Legacy plugin author migration question', 'Support bundle redaction concern', 'Suspected security advisory'))}
    for relative_path in app_platform_docs_check.PUBLIC_BETA_DOCS:
        public_beta_name = Path(relative_path).name
        (workspace / relative_path).write_text(public_beta_doc_text[public_beta_name] + '\n', encoding='utf-8')
    issue_dir = workspace / '.github/ISSUE_TEMPLATE'
    issue_dir.mkdir(parents=True, exist_ok=True)
    issue_text = '\n'.join(('name: Synthetic public beta feedback', 'labels:', '  - privacy/redaction-required', 'body:', '  - type: markdown', '    attributes:', '      value: |', '        Do not upload raw support bundles. Do not include exploit details publicly. Do not paste private insert URIs, private keys, tokens, raw app data, raw fetched content, raw signatures, or local absolute paths.', '        private security report security advisory or denylist event reviewer key compromise catalog signing key compromise app signing key compromise support bundle redaction failure', '  - type: checkboxes', '    id: redaction-confirmation', '    attributes:', '      label: Redaction confirmation', '      options:', '        - label: I confirm this report is redacted.', '          required: true', '  - type: input', '    id: release_id', '  - type: input', '    id: cryptad_version', '  - type: input', '    id: platform_api_contract_version', '  - type: input', '    id: catalog_channel', '  - type: input', '    id: catalog_id', '  - type: input', '    id: catalog_source_class', '  - type: input', '    id: mirror_id', '  - type: input', '    id: catalog_revision_edition', '  - type: input', '    id: signature_verification_status', '  - type: input', '    id: health_status', '  - type: input', '    id: rollback_attempted', '  - type: input', '    id: redacted_error_code', '  - type: input', '    id: app_id', '    attributes:', '      options: [queue-manager, publisher, site-publisher, profile-publisher, feed-reader, trust-graph, social-inbox]', '  - type: input', '    id: app_version', '  - type: input', '    id: target_app_version', '  - type: input', '    id: operation_being_attempted', '  - type: input', '    id: update_phase', '  - type: input', '    id: rollback_result', '  - type: input', '    id: migration_status', '  - type: input', '    id: app_data_backup_status', '  - type: input', '    id: subscription_id', '  - type: input', '    id: trust_social_document_profile_id', '  - type: input', '    id: support_bundle_digest', '  - type: input', '    id: support_bundle_schema_version', '  - type: input', '    id: diagnostic_summary_id', '  - type: input', '    id: consent_audit_event_id', '  - type: input', '    id: operator_recovery_action_id', '  - type: input', '    id: known_issue_id', '  - type: input', '    id: severity', '  - type: input', '    id: impact', '  - type: input', '    id: reproduction_steps', '  - type: input', '    id: expected_behavior', '  - type: input', '    id: actual_behavior', '  - type: input', '    id: redacted_evidence', '  - type: input', '    id: export_preview_status', '  - type: input', '    id: redaction_concern_category', '  - type: input', '    id: advisory_type', '  - type: input', '    id: affected_component', '  - type: input', '    id: public_safe_impact'))
    for template_path in app_platform_docs_check.ISSUE_TEMPLATES:
        path = workspace / template_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(issue_text, encoding='utf-8')
    beta_template = workspace / app_platform_docs_check.PUBLIC_BETA_RELEASE_NOTES_TEMPLATE
    beta_template.parent.mkdir(parents=True, exist_ok=True)
    beta_template.write_text('\n'.join((f'## {section}' for section in app_platform_docs_check.BETA_RELEASE_NOTES_SECTIONS)) + '\nNo private insert URIs, raw support bundles, raw app data, or local paths.\n', encoding='utf-8')
    known_issues_metadata = workspace / app_platform_docs_check.PUBLIC_BETA_KNOWN_ISSUES_METADATA
    known_issues_metadata.parent.mkdir(parents=True, exist_ok=True)
    write_json(known_issues_metadata, {'schemaVersion': 1, 'knownIssues': [{'knownIssueId': 'PBKI-EXAMPLE-001', 'status': 'open-example', 'severity': 'severity/medium', 'area': 'area/catalog', 'affectedChannels': ['stable-first-party'], 'affectedAppIds': [], 'affectedVersions': ['cryptad-beta-example'], 'firstSeenReleaseId': 'cryptad-beta-example', 'fixedInReleaseId': 'unfixed', 'workaroundSummary': 'Use digest and summary metadata only.', 'supportBundleEvidenceAllowed': 'digest-and-summary-only', 'redactionNotes': 'No raw data.', 'backlogLinkOrPlaceholder': 'BACKLOG-PUBLIC-BETA-EXAMPLE'}]})
    sample_dir = workspace / 'samples/third-party/hello-stable-app'
    (sample_dir / 'static').mkdir(parents=True, exist_ok=True)
    (sample_dir / 'review').mkdir(parents=True, exist_ok=True)
    (sample_dir / 'cryptad-app.properties').write_text('app.id=org.example.hello\napi.targetStability=stable\napi.experimentalCapabilitiesAccepted=false\napp.permissions=platform.contract.read\n', encoding='utf-8')
    (sample_dir / 'static/app.js').write_text('window.CryptaPlatform.api.get("platform/contract");\n', encoding='utf-8')
    (sample_dir / 'static/index.html').write_text('<section data-crypta-permission-summary>platform.contract.read</section>\n', encoding='utf-8')
    (sample_dir / 'README.md').write_text('crypta-app submission create\ncrypta-app submission pre-review\n', encoding='utf-8')
    for review_file_name in ('permission-rationale.md', 'sandbox-rationale.md', 'data-schema.md', 'backup-restore.md', 'security-notes.md', 'changelog.md'):
        (sample_dir / 'review' / review_file_name).write_text('fixture\n', encoding='utf-8')
    cert_readme = workspace / 'tools/release-certification/README.md'
    cert_readme.parent.mkdir(parents=True, exist_ok=True)
    cert_readme.write_text(first_party_docs, encoding='utf-8')
    plugin_fixture_dir = workspace / 'tools/release-certification/fixtures'
    plugin_fixture_dir.mkdir(parents=True, exist_ok=True)
    write_json(workspace / app_platform_docs_check.PUBLIC_BETA_SAFE_FEEDBACK_FIXTURE, {'supportIssueMetadata': {'release_id': 'cryptad-beta-example', 'support_bundle_digest': 'sha256:0123456789abcdef', 'diagnostic_summary_id': 'diag-example'}, 'catalogIncidentMetadata': {'catalog_id': 'crypta-first-party'}, 'appSpecificFeedbackMetadata': {'app_id': 'feed-reader'}, 'knownIssueEntry': {'knownIssueId': 'PBKI-EXAMPLE-001', 'status': 'open-example', 'severity': 'severity/medium', 'area': 'area/catalog', 'affectedChannels': ['stable-first-party'], 'affectedAppIds': [], 'affectedVersions': ['cryptad-beta-example'], 'firstSeenReleaseId': 'cryptad-beta-example', 'fixedInReleaseId': 'unfixed', 'workaroundSummary': 'Use digest and summary metadata only.', 'supportBundleEvidenceAllowed': 'digest-and-summary-only', 'redactionNotes': 'No raw data.', 'backlogLinkOrPlaceholder': 'BACKLOG-PUBLIC-BETA-EXAMPLE'}, 'betaReleaseNotesSnippet': {'release_id': 'cryptad-beta-example'}, 'feedbackToBacklogRecord': {'redaction_check': 'pass'}})
    public_beta_negative_payloads = {'public-beta-feedback-redaction-private-insert-uri.json': {'privateInsertUri': 'USK@abcdefghijklmno,qrstuvwxyz0123456789ABCDEFG/name/0'}, 'public-beta-feedback-redaction-private-key.json': {'privateKey': '-----BEGIN PRIVATE KEY-----\nfixture\n-----END PRIVATE KEY-----'}, 'public-beta-feedback-redaction-app-token.json': {'appToken': '<redacted> abcdef0123456789'}, 'public-beta-feedback-redaction-browser-session-token.json': {'browserSessionToken': 'browser-session-secret'}, 'public-beta-feedback-redaction-authorization-header.json': {'header': 'Authorization: Bearer concrete-token-value'}, 'public-beta-feedback-redaction-cookie.json': {'header': 'Cookie: sid=abcdef012345'}, 'public-beta-feedback-redaction-raw-feed.json': {'rawFeedDocument': 'private feed'}, 'public-beta-feedback-redaction-raw-profile.json': {'rawProfileDocument': 'private profile'}, 'public-beta-feedback-redaction-raw-trust.json': {'rawTrustStatement': 'private trust'}, 'public-beta-feedback-redaction-raw-social.json': {'rawSocialMessage': 'private social'}, 'public-beta-feedback-redaction-raw-app-data.json': {'rawAppDataValue': 'private app data'}, 'public-beta-feedback-redaction-local-path.json': {'path': '/home/example/.crypta/private.json'}, 'public-beta-feedback-redaction-nested-backup.json': {'rawSupportBundle': {'nestedBackup': 'private backup'}}}
    for fixture_path in app_platform_docs_check.PUBLIC_BETA_NEGATIVE_FEEDBACK_FIXTURES:
        fixture_name = Path(fixture_path).name
        write_json(workspace / fixture_path, public_beta_negative_payloads[fixture_name])
    plugin_fixture_payloads = {'plugin-migration-redaction-safe.json': {'legacyPluginId': 'legacy.example', 'newAppId': 'app-id.example', 'publicReadUri': 'crypta:USK@<example-public-read-key>/profile/1/profile.json', 'contentDigest': 'sha256:example-digest'}, 'plugin-migration-redaction-private-insert-uri.json': {'privateInsertUri': 'crypta:USK@PRIVATEINSERTURI12345/example/0'}, 'plugin-migration-redaction-private-key.json': {'keyMaterial': '-----BEGIN PRIVATE KEY-----\nfixture\n-----END PRIVATE KEY-----'}, 'plugin-migration-redaction-general-credentials.json': {'privateKey': 'MC4CAQAwBQYDK2VwBCIEIAabcdefghijklmnop', 'formPassword': 'synthetic-form-password', 'Cookie': 'sid=synthetic-cookie-secret', 'X-Crypta-App-Session': 'synthetic-browser-session-secret'}, 'plugin-migration-redaction-app-token.json': {'CRYPTAD_APP_TOKEN': 'synthetic-token-1234567890'}, 'plugin-migration-redaction-browser-session-token.json': {'browserSessionToken': 'synthetic-browser-session-token'}, 'plugin-migration-redaction-raw-social-message.json': {'rawSocialMessage': 'synthetic-private-message-body'}, 'plugin-migration-redaction-raw-trust-statement.json': {'rawTrustStatement': 'synthetic-private-trust-statement'}, 'plugin-migration-redaction-raw-profile-feed-document.json': {'rawProfileDocument': 'synthetic-private-profile-document', 'rawFeedSnapshot': 'synthetic-private-feed-snapshot'}, 'plugin-migration-redaction-raw-app-data-value.json': {'rawAppDataValue': 'synthetic-private-app-data-value'}, 'plugin-migration-redaction-local-path.json': {'exportPath': '/home/example/.crypta/plugin-export.json'}, 'plugin-migration-redaction-raw-fproxy-html.json': {'rawFproxyHtml': '<html><body>fixture</body></html>'}, 'plugin-migration-redaction-old-plugin-export-secrets.json': {'oldPluginExport': 'synthetic-plugin-export-with-secrets'}, 'plugin-migration-redaction-raw-artifact-separators.json': {'raw_social_message': 'synthetic-private-message-body', 'raw-trust-statement': 'synthetic-private-trust-statement', 'old_plugin_export': 'synthetic-plugin-export-with-secrets', 'raw profile document': 'synthetic-private-profile-document'}, 'plugin-migration-redaction-partial-redaction.json': {'rawSocialMessage': '<redacted> synthetic-private-message-body'}, 'plugin-migration-redaction-multiline-raw-payload.json': {'rawSocialMessage': {'type': 'crypta.social.message.v1', 'body': 'synthetic-private-message-body'}}, 'plugin-migration-redaction-java-file-uri.json': {'exportPath': 'file:/home/example/plugin-export.json'}}
    for fixture_name, fixture_payload in plugin_fixture_payloads.items():
        write_json(plugin_fixture_dir / fixture_name, fixture_payload)
    runbook_text = '# Production Security Response Runbook\n\nVulnerable app version\nMalicious or compromised app version\nApp signing key compromise\nReviewer key compromise with revoked reviewer handling\nReview receipt revocation\nCatalog signing key compromise or rotation with unknown/untrusted/compromised key fail-closed behavior\nMalicious catalog entry or catalog metadata compromise\nEmergency replacement app publication\nSafe uninstall/update guidance\nSupport bundle intake and redaction handling\n\nTrigger signals Required evidence Immediate containment Catalog/advisory/denylist actions Review/reviewer/revocation actions App update scheduler expected behavior Web Shell/operator UX expected behavior Recovery guidance Redaction requirements Release note fields Verification steps Rollback or follow-up\n\nEmergency catalog update workflow covers advisory creation, exact denylist records, reviewer revocation, dry-run signed catalog candidates, redaction checks, and release notes.\n'
    (docs / 'production-security-response-runbook.md').write_text(runbook_text, encoding='utf-8')
    template_dir = docs / 'templates'
    template_dir.mkdir(parents=True, exist_ok=True)
    (template_dir / 'security-release-notes.md').write_text('# Security Release Notes\n\nAdvisory id\nAffected apps and versions\nSeverity\nImpact summary\nContainment\nUpdate guidance\nSafe uninstall guidance\nReplacement app/version\nReview\nCatalog\nSupport bundle guidance\nRedaction note\nCredits\n', encoding='utf-8')
    drill_template = {'severity': 'high', 'trigger': 'deterministic drill trigger', 'containmentActions': ['contain'], 'catalogActions': ['publish advisory'], 'reviewActions': ['record reviewer state'], 'operatorActions': ['show warning'], 'schedulerExpectations': ['block unsafe automatic apply'], 'redactionRequirements': ['omit private material'], 'verificationEvidence': ['self-test evidence'], 'releaseNotesTemplate': 'docs/templates/security-release-notes.md'}
    runbook_model = {'schemaVersion': 1, 'kind': 'cryptad-production-security-response-runbook', 'drills': [{'id': drill_id, **drill_template} for drill_id in PRODUCTION_SECURITY_REQUIRED_DRILLS]}
    (workspace / 'tools/release-certification/cryptad_certification/engines').mkdir(parents=True, exist_ok=True)
    (workspace / 'tools/release-certification/production-security-response-runbook.json').write_text(json.dumps(runbook_model, sort_keys=True) + '\n', encoding='utf-8')
    (workspace / 'tools/release-certification/certify.py').write_text(
        "#!/usr/bin/env python3\n",
        encoding='utf-8',
    )
    (workspace / 'tools/release-certification/cryptad_certification/engines/security_response_runbook_impl.py').write_text("def verify_runbook(): pass\ndef drill_create(): pass\ndef drill_verify(): pass\ndef advisory_template(): pass\nKIND = 'cryptad-security-response-drill'\n", encoding='utf-8')
    (workspace / 'tools/release-certification/cryptad_certification/engines/production_beta_release_fixture.py').write_text("FIRST_PARTY_MAINTENANCE_POLICY_FILE = 'first-party-app-maintenance-policy.json'\ndef maintenance_policy_args(policy):\n    return ['--maintenance-owner', policy['maintenance']['owner']]\nCRITICAL_PRODUCTION_BETA_EVIDENCE_IDS = ('app-catalog.first-party-maintenance-policy', 'first-party-app.beta-quality-pass', 'app-platform.privacy-preserving-beta-diagnostics')\n", encoding='utf-8')
    (workspace / 'tools/release-certification/cryptad_certification/engines/release_certification_fixture.py').write_text("ECOSYSTEM_RC_REQUIRED_EVIDENCE_IDS = ('app-platform.privacy-preserving-beta-diagnostics',)\nECOSYSTEM_RC_REDACTION_EVIDENCE_IDS = ('app-platform.privacy-preserving-beta-diagnostics',)\nMatrixRowSpec(id='privacy-preserving-diagnostics-risk', required_evidence_ids=('app-platform.privacy-preserving-beta-diagnostics',))\n", encoding='utf-8')
    (workspace / 'tools/release-certification/cryptad_certification/engines/production_beta_go_no_go_dashboard_fixture.py').write_text("CRITICAL_PRODUCTION_BETA_EVIDENCE_IDS = ('app-platform.privacy-preserving-beta-diagnostics',)\nDOMAIN_SPECS = ({'id': 'privacy-preserving-diagnostics-risk', 'evidenceIds': ('app-platform.privacy-preserving-beta-diagnostics',)},)\n", encoding='utf-8')
    policy_apps = {}
    for app_id, expected_policy in FIRST_PARTY_MAINTENANCE_EXPECTATIONS.items():
        policy_apps[app_id] = {'channel': 'stable', 'supportStatus': 'supported', 'deprecationStatus': 'none', 'minimumCryptaVersion': None, 'maximumCryptaVersion': None, 'maintenance': {'owner': 'crypta-core', 'ownerUri': FIRST_PARTY_MAINTENANCE_OWNER_URI, 'supportLevel': expected_policy['supportLevel'], 'dataSchemaPolicy': expected_policy['dataSchemaPolicy'], 'migrationPolicy': expected_policy['migrationPolicy'], 'backupRestore': expected_policy['backupRestore'], 'securityPolicy': expected_policy['securityPolicy'], 'deprecationPolicy': expected_policy['deprecationPolicy'], 'supportUri': FIRST_PARTY_SUPPORT_URI}}
    write_json(workspace / FIRST_PARTY_MAINTENANCE_POLICY_PATH, {'schemaVersion': 1, 'owner': 'crypta-core', 'apps': policy_apps})
    readiness_apps: dict[str, Any] = {}
    for app_id, expected_readiness in FIRST_PARTY_BETA_EXPECTATIONS.items():
        readiness_apps[app_id] = {'betaReadiness': {'status': 'ready', 'owner': FIRST_PARTY_MAINTENANCE_OWNER, 'qualityLevel': 'beta', 'emptyState': 'required', 'errorState': 'bounded-required', 'retryAction': 'required', 'recoveryAction': 'operator-recovery-link', 'permissionRationale': 'required', 'supportMetadata': 'required', 'accessibility': 'basic-pass', 'uiConsistency': 'design-system-pass', 'diagnostics': 'redacted-summary-only', **expected_readiness}}
    write_json(workspace / FIRST_PARTY_BETA_READINESS_PATH, {'schemaVersion': 1, 'evidenceId': FIRST_PARTY_BETA_QUALITY_EVIDENCE_ID, 'apps': readiness_apps})
    (docs / 'legacy-plugin-freeze-policy.md').write_text('This policy defines the production RC freeze boundary for the removed legacy plugin system. The old in-process plugin runtime is frozen and removed. Do not add new in-core plugin APIs or new daemon-core plugin APIs. Do not restore network.crypta.pluginmanager, old plugin ABI classes, plugin toadlets, old plugin admin pages, or old FCP plugin command compatibility. UnsupportedPluginMessage is the narrow boundary for historical FCP plugin command names; those names must keep deterministic unsupported responses and must not execute plugin code. Legacy docs under docs/legacy are historical only and not current implementation commitments. Migration uses out-of-process apps, Platform API, signed catalogs, AppVault, content subscriptions, durable app data, Trust Graph Local RC, and app-service grants. See legacy-plugin-migration-cookbook.md for the public-beta executable path. This is not full WoT, not old WebOfTrust plugin compatibility, not Freetalk/Sone/Freemail compatibility, not encrypted mail transport, and not a daemon-core social or mail protocol.\n', encoding='utf-8')
    (docs / 'legacy-plugin-migration-guide.md').write_text('See legacy-plugin-freeze-policy.md, legacy-plugin-migration-cookbook.md and plugin-system.md for the production RC freeze policy. The old plugin runtime removed status is intentional. There is no old plugin ABI compatibility and no old FCP plugin command compatibility. No new in-core plugin APIs will be added. WebOfTrust-like and WoT-like migration maps to Trust Graph Local RC, durable trust graph storage, content subscriptions, AppVault identity grants, durable app data, and app-service grants for trust.score. Freetalk/Sone-like migration maps to Social Inbox RC, Profile Publisher, Feed Reader, content subscriptions, app data, and Trust Graph annotations. Freemail-like migration uses Social Inbox as a bounded spike and is not encrypted mail transport or Freemail protocol compatibility. Distribution uses signed catalog entries, signed bundles, review receipt evidence, and review governance. The guide links to social-inbox-reference-app.md. Third-party migration uses third-party-developer-beta-program.md and third-party-app-submission-checklist.md with the Platform API 1.0 stable baseline when possible. Retained FProxy browse is an emergency and compatibility fallback, not a new plugin API. Legacy docs under docs/legacy are historical only and are not implementation commitments. This is not full WoT, not old WebOfTrust plugin compatibility, not Freetalk/Sone/Freemail compatibility, not encrypted mail transport, and not a daemon-core social or mail protocol.\n', encoding='utf-8')
    (docs / 'plugin-system.md').write_text('Production RC freeze policy: the old in-process plugin runtime is frozen and removed. There are no new in-core plugin APIs, no old plugin ABI compatibility, and no old FCP plugin command compatibility. Legacy FCP plugin command names must keep failing deterministically through UnsupportedPluginMessage. Legacy plugin migrations should use legacy-plugin-freeze-policy.md, legacy-plugin-migration-guide.md, legacy-plugin-migration-cookbook.md, out-of-process apps, Platform API, signed catalogs, AppVault, content subscriptions, durable app data, Trust Graph Local RC, and app-service grants. Legacy docs under docs/legacy are historical only and not an implementation commitment. This is not full WoT, not old WebOfTrust plugin compatibility, not Freetalk/Sone/Freemail compatibility, not encrypted mail transport, and not a daemon-core social or mail protocol.\n', encoding='utf-8')
    (docs / 'templates').mkdir(parents=True, exist_ok=True)
    (docs / 'templates/plugin-migration-plan.md').write_text('legacyPluginId\nnewAppId\nstateClasses\nmanifestCapabilities\nappDataNamespaces\ncontentSubscriptions\nidentityGrants\nappServiceDependencies\nmigrationSteps\nbackupRestorePolicy\nreviewEvidence\nredactionPolicy\nknownNonGoals\n', encoding='utf-8')
    plugin_examples_dir = docs / 'examples/plugin-migration'
    plugin_examples_dir.mkdir(parents=True, exist_ok=True)
    (docs / 'legacy-plugin-migration-cookbook.md').write_text('# Legacy plugin migration cookbook\n\nOld plugin runtime remains removed and frozen. No compatibility shim, old plugin ABI/FCP command compatibility, WebOfTrust/Freetalk/Sone/Freemail protocol compatibility, daemon-core compatibility shims, raw FProxy scraping, ambient localhost RPC, direct daemon internals, private-key export, or unbounded crawling is promised. UnsupportedPluginMessage is the deterministic unsupported boundary.\n\n## Decision tree\nLegacy plugin function -> needs local UI? -> app-owned UI. exposes a capability? -> app-service provider. consumes another service? -> app-service consumer. publishes documents? -> content format profile. keeps mutable local state? -> app-data namespace and migration. signs identity or social documents? -> AppVault identity grant. follows sources? -> content subscription. distributes to users? -> review and catalog flow. unsupported daemon hook? -> unsupported; no public-beta compatibility path is promised.\n\n## Migration matrix\nOld plugin UI maps to app-owned UI. Plugin config and state maps to durable app data. Plugin identity and secrets maps to AppVault. Plugin trust score lookup maps to Trust Graph Local RC trust.score. Plugin social feed maps to Social Inbox RC. Old FCP plugin command maps to UnsupportedPluginMessage only.\n\n## Unsupported forever\nin-process daemon hooks; old plugin ABI/FCP command compatibility; ambient localhost RPC; raw FProxy scraping; direct daemon internals; private-key export; unbounded crawling. Retained FProxy browse remains retained and does not create a new plugin API.\n\n## WebOfTrust-like trust annotations\nWebOfTrust-like migration maps to Trust Graph Local RC and trust.score. The replacement is local-only; no global moderation, routing policy, peer-selection policy, full WoT, old WebOfTrust API, crawler, or daemon-core trust store. Operator consent plus service dependency and grant bundle approval are required. Importing statements is a Trust Graph app capability. Diagnostics must not include raw trust statements or signatures.\n\n## Freetalk/Sone-like social, forum, and profile flows\nFreetalk/Sone-like migration maps to Social Inbox RC, crypta.social.message.v1, crypta.social.outbox.v1, AppVault, content subscriptions, durable app data, and optional Trust Graph trust.score grants. It is not Freetalk/Sone protocol compatibility, no daemon-core message store, and no global moderation.\n\n## Freemail-like future Mail app pattern\nFreemail-like future Mail app pattern has no implementation in PR-279. Social Inbox is a bounded UX reference only, not encrypted mail transport and no Freemail protocol compatibility.\n\n## Data, identity, and subscription preservation\nInventory old plugin state, define app-data namespaces and schema versions, support dry-run mode, provide backup/export before destructive migration, avoid private identity export, avoid private insert URI persistence, bind operator consent to migration and grant deltas, and document what cannot be migrated automatically.\n\n## App-service dependency examples\nApp-service dependency examples cover provider unavailable, grant revoked or expired, provider descriptor changed, and no app-service request bodies or tokens in support bundles. Social Inbox consumes trust.score through operator-approved grants.\n\n## Beta submission flow\ncrypta-app init, crypta-app test, crypta-app ui lint, crypta-app compat verify, crypta-app pack, crypta-app submission create, crypta-app submission verify, and crypta-app submission pre-review.\n\nold plugin ABI/FCP/runtime/toadlet/admin surfaces are not used.\n', encoding='utf-8')
    for example_name, example_text in {'wot-like-trust-graph-app.md': 'Trust Graph Local RC trust.score app-service grant example.\n', 'social-inbox-migration.md': 'Social Inbox RC crypta.social.message.v1 migration example.\n', 'future-mail-app-pattern.md': 'Future Mail pattern not implemented in PR-279.\n', 'content-publisher-migration.md': 'content.insert.app-document example excluding private insert URIs.\n', 'app-service-grant-migration.md': 'trust.score provider unavailable grant revoked descriptor changed.\n', 'plugin-author-submission-flow.md': 'crypta-app submission pre-review catalog candidate flow.\n'}.items():
        (plugin_examples_dir / example_name).write_text(example_text, encoding='utf-8')
    adapter_fcp_dir = workspace / 'adapter-fcp/src/main/java/network/crypta/clients/fcp'
    adapter_fcp_dir.mkdir(parents=True, exist_ok=True)
    (adapter_fcp_dir / 'UnsupportedPluginMessage.java').write_text('final class UnsupportedPluginMessage { String text = "Plugin system has been removed; this command is no longer supported."; void run(FCPConnectionHandler handler) { handler.send(new ProtocolErrorMessage(ProtocolErrorMessage.INVALID_MESSAGE, false, text, null, false)); } }\n', encoding='utf-8')
    (adapter_fcp_dir / 'FCPMessage.java').write_text('class FCPMessage { Object create(String name, SimpleFieldSet fs) { return switch(name) { case "FCPPluginMessage" -> new UnsupportedPluginMessage(fs, "FCPPluginMessage"); case "GetPluginInfo" -> new UnsupportedPluginMessage(fs, "GetPluginInfo"); case "LoadPlugin" -> new UnsupportedPluginMessage(fs, "LoadPlugin"); case "ReloadPlugin" -> new UnsupportedPluginMessage(fs, "ReloadPlugin"); case "RemovePlugin" -> new UnsupportedPluginMessage(fs, "RemovePlugin"); default -> null; }; } }\n', encoding='utf-8')
    registry = workspace / 'adapter-http-legacy-admin/src/main/java/network/crypta/clients/http/LegacyAdminRetirementRegistry.java'
    registry.parent.mkdir(parents=True, exist_ok=True)
    registry.write_text((Path(__file__).parent / 'fixtures' / 'self-test-legacy-registry.java-fragment').read_text(encoding='utf-8'), encoding='utf-8')
    legacy_docs = workspace / 'docs/legacy-retirement-plan.md'
    legacy_docs.parent.mkdir(parents=True, exist_ok=True)
    legacy_docs.write_text('legacy-admin.removal-wave-1 documents that removed routes return replacement responses when the replacement is reachable and render legacy fallback when the replacement is unavailable. legacy-admin.removal-wave-2 documents that safe reads redirect when the replacement is reachable, mutating legacy alert bulk actions and core-update installer and package-store actions remain fallback, and during Wave 2, the raw diagnostic export remained retained. legacy-admin.removal-wave-3 documents that /seclevels/ safe reads redirect to /app/node/#security when Web Shell security is available. Security-level mutating requests keep legacy fallback; legacy fallback remains for master-password, database/password-file, high physical security, and recovery flows. Wave 3 does not use prefix-family matching for security routes. A bootstrap-resolved explicit fallback link remains in the Security panel for legacy security forms with legacyFallback=security-levels, and arbitrary query strings still receive replacement redirects. legacy-admin.removal-wave-4 documents that diagnostic is the only Wave 4 route. Web Shell diagnostics at /app/node/#diagnostics is primary, while the raw diagnostic export remains a plain-text support or emergency fallback only through the exact bootstrap-resolved diagnostic fallback marker. legacy-admin.removal-wave-5 documents final admin surface readiness with no additional promoted route ids, because all remaining routes are retained, pending, infrastructure, browse, support, or startup recovery fallback. legacy-admin.final-admin-surface documents the final admin surface policy: legacy admin is maintenance-only after Wave 5, daily operator workflows are Web Shell or app-first, and no new legacy admin surfaces should be added. legacy-admin.browse-retained documents that FProxy browse and content rendering remain retained and content filter remains retained. Retained browse does not create a new plugin API; former plugin authors use legacy-plugin-migration-cookbook.md. legacy-admin.emergency-fallback-retained documents startup and recovery fallback, diagnostic support and emergency fallback, and redaction for support bundles. Query strings, request bodies, tokens, private insert URIs, raw diagnostic output, raw fetched content, app data, and local paths remain excluded from Wave 5 evidence. Startup wizard and emergency fallback remain pending. Node-to-node messages remain pending. FProxy browse remains retained, FProxy browse and content rendering remain retained, content filter remains retained, and retained and pending legacy routes remain reachable.\n', encoding='utf-8')
    legacy_admin_dir = workspace / 'adapter-http-legacy-admin/src/main/java/network/crypta/clients/http'
    (legacy_admin_dir / 'LegacyAdminRemovalPolicy.java').write_text('class LegacyAdminRemovalPolicy { boolean matchesCanonicalPageOrSlashlessAlias; boolean matchesRemovalScope; boolean explicitRemovalChildPaths; boolean blockMutatingRequests; boolean replacementAvailable; boolean isStaticAppUiAvailable; boolean primaryUiRoot; String legacyFallback = "legacyFallback=security-levels"; String diagnosticFallback = "legacyFallback=diagnostic-export"; boolean exactFallback = diagnosticFallback.equals(uri.getRawQuery()); String security = "security-levels"; boolean webShellReplacementAvailable; String diagnostic = "diagnostic"; String s = "LegacyAdminRemovalScope EXPLICIT_CHILDREN PREFIX_FAMILY"; String m = "GET HEAD"; Object d = LegacyAdminRemovalDecision.redirect(null); Object b = LegacyAdminRemovalDecision.blockedMutation(null); boolean safe(String method) { return !isMutatingRequestMethod(method); } }\n', encoding='utf-8')
    (legacy_admin_dir / 'LegacyAdminReplacementResponse.java').write_text('class LegacyAdminReplacementResponse { String link = "replacementUrl"; }\n', encoding='utf-8')
    (legacy_admin_dir / 'WebShellToadlet.java').write_text('class WebShellToadlet { Object create(Object links) { return createNodeManagementBootstrap(legacySecurityLevelsPath(), legacyDiagnosticPath(), links); } Object createNodeManagementBootstrap(String legacySecurityLevelsPath, String legacyDiagnosticPath, Object links) { return WebShellBootstrap.nodeManagement(\n legacySecurityLevelsPath, legacyDiagnosticPath, links); } String legacySecurityLevelsPath() { return LegacyAdminRetirementRegistry.require("security-levels").legacyPath(); } String legacyDiagnosticPath() { return LegacyAdminRetirementRegistry.require("diagnostic").legacyPath(); } }\n', encoding='utf-8')
    legacy_admin_test_dir = workspace / 'adapter-http-legacy-admin/src/test/java/network/crypta/clients/http'
    legacy_admin_test_dir.mkdir(parents=True, exist_ok=True)
    (legacy_admin_test_dir / 'LegacyAdminRemovalPolicyTest.java').write_text('class LegacyAdminRemovalPolicyTest { String fallback = "legacyFallback=diagnostic-export"; String nonExact = "legacyFallback=diagnostic-export&token=secret"; String securityFallback = "legacyFallback=security-levels"; String slashless = "/diagnostic"; String subpath = "/diagnostic/requesters"; String securityChild = "/seclevels/network"; String retained = "/ /CHK@abc /SSK@abc /USK@abc /filterfile/ /filter-browse/ /wizard/ /wiz/ /send_n2ntm/ /n2nm-browse/ /chat/ /translation/ /help/ /app/node/ /apps/ /apps/queue-manager/ /api/v1/diagnostics /api/v1/wizard/first-time /api/v1/operator/recovery/actions /api/v1/operator/support-bundle"; void decide_whenWaveFiveFinalSurfaceRetainedRouteRequested_expectNoDecision() {} Object waveFiveRetainedInfrastructureAndFallbackRoutes() { return retained; } String replacement = "/app/node/#diagnostics"; }\n', encoding='utf-8')
    (legacy_admin_test_dir / 'LegacyAdminRetirementRegistryTest.java').write_text('class LegacyAdminRetirementRegistryTest { String waveFour = "REMOVAL_WAVE_4 diagnostic"; String waveFive = "REMOVAL_WAVE_5 phase-10-pr-265"; void removalWaveSurfaces_whenWaveFiveRequested_expectNoUnprovenRoutePromotions() {} void finalSurfacePolicy_whenRemovedAdminRequested_expectAllRemovalWavesRepresented() {} void finalSurfacePolicy_whenFallbacksRequested_expectRecoveryAndSupportExplicit() {} void findByLegacyPath_whenFProxyBrowseRouteRequested_expectNoRetirementSurface() {} String replacement = "/app/node/#diagnostics"; }\n', encoding='utf-8')
    legacy_browse_test_dir = workspace / 'adapter-http-legacy-browse/src/test/java/network/crypta/clients/http'
    legacy_browse_test_dir.mkdir(parents=True, exist_ok=True)
    (legacy_browse_test_dir / 'LegacyFProxyBrowseRouteRegistrarTest.java').write_text('class LegacyFProxyBrowseRouteRegistrarTest { String root = "/"; String phase = "LegacyHttpBrowseRouteRegistrar.Phase.QUEUE_FILTER_ROUTES"; String routes = "ContentFilterToadlet LocalFileFilterToadlet"; }\n', encoding='utf-8')
    (legacy_admin_test_dir / 'WebShellToadletBootstrapTest.java').write_text('class WebShellToadletBootstrapTest { String marker = "legacyFallback=diagnostic-export"; String path = "legacyDiagnosticPath"; }\n', encoding='utf-8')
    (legacy_admin_dir / 'LegacyAdminUsageRecorder.java').write_text('class LegacyAdminUsageRecorder { Object a = LegacyAdminUsageEvent.REPLACEMENT_RESPONSE; }\n', encoding='utf-8')
    usage_dto = workspace / 'runtime-spi/src/main/java/network/crypta/runtime/spi/LegacyAdminSurfaceUsage.java'
    usage_dto.parent.mkdir(parents=True, exist_ok=True)
    usage_dto.write_text('record LegacyAdminSurfaceUsage(long replacementResponseCount, long blockedMutatingRequestCount, long fallbackRenderCount, long retainedOrPendingRenderCount, String removalScope, int scopeExpandedInWave) {}\n', encoding='utf-8')
    diagnostics_handler = workspace / 'platform-api/src/main/java/network/crypta/platform/api/diagnostics/DiagnosticsApiHandler.java'
    diagnostics_handler.parent.mkdir(parents=True, exist_ok=True)
    diagnostics_handler.write_text('class DiagnosticsApiHandler { String a = "replacementResponseCount blockedMutatingRequestCount fallbackRenderCount retainedOrPendingRenderCount removalScope scopeExpandedInWave plainTextExportAvailable"; Map<String, Object> supportSummary() { return Map.of("plainTextExportAvailable", true); } }\n', encoding='utf-8')
    app_vault_doc = workspace / APP_VAULT_DOC
    app_vault_doc.write_text('The app secret and identity vault defines vault.secrets.read, vault.secrets.write, vault.identities.read, vault.identities.create, and vault.identities.use for app-facing routes. vault.identities.manage is host/operator-only identity management. It distinguishes app-owned identities from shared identities. Process callers use CRYPTAD_APP_TOKEN, while browser callers use app browser sessions. At-rest local protection has limits and depends on the host account. Grant lifecycle checks cover update, rollback, uninstall, and reinstall. Audit and redaction omit secret values and identity private material. Future content, social, and mail features can use the same extension point. POST /api/v1/app-vault/identities is browser-safe when the calling app has vault.identities.create. POST /api/v1/app-vault/identities/{identityId}/profile-document uses vault.identities.read and vault.identities.use to create a profile document. Evidence omits raw request bodies, private keys, and signatures.\n', encoding='utf-8')
    devtools_dir = workspace / 'platform-devtools/src/main/java/network/crypta/platform/devtools'
    devtools_dir.mkdir(parents=True, exist_ok=True)
    (devtools_dir / 'DevtoolsCapabilityVocabulary.java').write_text('\n'.join(APP_VAULT_CAPABILITIES) + '\n', encoding='utf-8')
    (devtools_dir / 'CryptaAppCli.java').write_text('@Option(names = {"--app-id", "--id"}) String appId;\nclass InitCommand { String template = "static-basic, hello-stable, queue-dashboard, publisher, vault-profile"; }\n@Command(name = "dev") class DevCommand {}\n@Command(name = "test") class AppTestCommand {}\n@Command(name = "generate") class KeysGenerateCommand {}\n@Command(name = "review") class ReviewCommand { String s = "ReviewSignCommand ReviewVerifyCommand review fingerprint Receipt revocations: receiptRevocations="; }\n@Command(name = "entry") class CatalogEntryCommand { String options = "--channel --support-status --security-advisory --maximum-crypta-version --maintenance-owner --maintenance-support-level --maintenance-data-schema-policy --maintenance-migration-policy --maintenance-backup-restore --maintenance-security-policy --maintenance-deprecation-policy --maintenance-support-uri"; }\nclass CatalogCreateCommand { String options = "--security-advisory-record --security-denylist-entry"; }\n@Command(name = "publish-usk") class PublishUskCommand { String dry = "--dry-run"; String live = "--live"; String insertEnv = "--private-insert-uri-env"; String insertFile = "--private-insert-uri-file"; String passwordEnv = "--form-password-env"; String passwordFile = "--form-password-file"; String s = "PublicationPlanWriter LiveUskPublicationService loadSecureText requires exactly one of --dry-run or --live"; }\nclass SubmissionIntakeCommand { String s = "SubmissionIntakeImportCommand SubmissionIntakeListCommand SubmissionIntakeAssignCommand SubmissionIntakePreReviewCommand SubmissionIntakeDecideCommand SubmissionIntakeStageCandidateCommand SubmissionIntakeInstallSmokeCommand pre-review.json submission-verification.json api-compatibility.json ui-lint.json redaction-scan.json artifact-manifest.json candidate-manifest.json candidate-review-receipt.properties candidate-transparency-log.jsonl catalog candidate does not expose third-party review metadata caution catalog candidates require --allow-caution installSmoke=pending install-smoke candidate-install-smoke.json recordInstallSmokePassed Beta catalog install smoke passed crypta-beta-catalog-install-smoke"; }\n', encoding='utf-8')
    (devtools_dir / 'AppTemplateKind.java').write_text('STATIC_BASIC HELLO_STABLE("hello-stable") QUEUE_DASHBOARD PUBLISHER VAULT_PROFILE List.of("platform.contract.read") static-basic queue-dashboard publisher vault-profile\n', encoding='utf-8')
    (devtools_dir / 'AppTemplateScaffolder.java').write_text('STATIC_BASIC HELLO_STABLE QUEUE_DASHBOARD PUBLISHER VAULT_PROFILE platform.api.get("platform/contract")\n', encoding='utf-8')
    (devtools_dir / 'AppTestSuite.java').write_text('class AppTestSuite { String s = "dev.bootstrap-smoke AppTestReport"; }\n', encoding='utf-8')
    (devtools_dir / 'DeveloperKeyGenerator.java').write_text('class DeveloperKeyGenerator { String s = "Ed25519 trusted.keys.version=1"; }\n', encoding='utf-8')
    (devtools_dir / 'CatalogEntryDescriptorGenerator.java').write_text('class CatalogEntryDescriptorGenerator { String s = "artifact.path permissions.rationale. --channel --support-status --security-advisory maximumCryptaVersion --maintenance-owner --maintenance-support-level --maintenance-data-schema-policy --maintenance-migration-policy --maintenance-backup-restore --maintenance-security-policy --maintenance-deprecation-policy --maintenance-support-uri api.targetStability"; }\n', encoding='utf-8')
    (devtools_dir / 'PublicationPlanWriter.java').write_text('class PublicationPlanWriter { String s = "Crypta Catalog USK Publication Plan"; }\n', encoding='utf-8')
    (devtools_dir / 'PublicationInputValidator.java').write_text('class PublicationInputValidator { String s = "crypta:USK@.../ cryptad-app-catalog.properties cryptad-app-catalog.signature"; }\n', encoding='utf-8')
    (devtools_dir / 'LiveUskPublicationService.java').write_text('class LiveUskPublicationService { Object v = PublicationInputValidator.validate(); String s = "AppCatalogVerifier.verify requirePrivateInsertUri"; }\n', encoding='utf-8')
    (devtools_dir / 'PlatformApiLiveUskPublisher.java').write_text('class PlatformApiLiveUskPublisher { String s = "queue/inserts/directory sourcePath insertUri COMPAT_CURRENT content/fetch contentBase64 live_publish_verification_failed followRedirects(HttpClient.Redirect.NEVER)"; }\n', encoding='utf-8')
    (devtools_dir / 'LiveUskPublicationResult.java').write_text('record LiveUskPublicationResult(String catalogSha256, String signatureSha256, String catalogSigningKeyId, String catalogInsertStatus, String schedulerRefreshVerificationStatus) {}\n', encoding='utf-8')
    (devtools_dir / 'LiveUskPublicationResultWriter.java').write_text('class LiveUskPublicationResultWriter { String s = "catalogSha256 signatureSha256 catalogSigningKeyId catalogInsertStatus schedulerRefreshVerificationStatus"; }\n', encoding='utf-8')
    devserver_dir = devtools_dir / 'devserver'
    devserver_dir.mkdir(parents=True, exist_ok=True)
    (devserver_dir / 'CryptaAppDevServer.java').write_text('class CryptaAppDevServer { boolean allowNonLoopback; }\n', encoding='utf-8')
    (devserver_dir / 'DevServerConfig.java').write_text('class DevServerConfig { String host = "127.0.0.1"; }\n', encoding='utf-8')
    (devserver_dir / 'MockPlatformApi.java').write_text('class MockPlatformApi { String s = "invalid_app_browser_session X-Crypta-App-Session /trust-graph/status /trust-graph/anchors /trust-graph/import /trust-graph/score "; boolean b = suffix.equals("/platform/contract"); }\n', encoding='utf-8')
    (devserver_dir / 'MockPlatformApiFixtures.java').write_text('class MockPlatformApiFixtures { String s = "platform-contract.json stableBaseline platform.contract.read"; }\n', encoding='utf-8')
    toolkit_test_dir = workspace / 'platform-devtools/src/test/java/network/crypta/platform/devtools'
    toolkit_test_dir.mkdir(parents=True, exist_ok=True)
    (toolkit_test_dir / 'DeveloperBetaToolkitCliTest.java').write_text('void test_whenFreshStaticTemplateCheckedStrict_expectPassingHumanAndJsonReport() {}\nvoid catalogEntryAndPublishUsk_whenSignedArtifactsPrepared_expectOfflinePlan() {}\nvoid devServer_whenStaticAppServed_expectBootstrapStaticAndSessionProtectedApi() {}\nvoid publish_whenFakePublisherSucceeds_expectSanitizedSummaryAndRetainedStaging() {}\nvoid publish_whenInsertIsOnlyQueued_expectStagingRetainedWithoutPathInSummary() {}\nvoid publish_whenPrivateInsertUriDoesNotMatchPublicSource_expectFailureWithoutPublisherOrSummary() {}\nvoid init_whenBetaTemplatesRequested_expectStrictTestCleanStaticApps() { String s = "hello-stable platform.contract.read"; }\nString e = "private insert URI must be configured by exactly one env or file source";\nString w = "staging_sidecars_retained_until_live_insert_completion";\nvoid redaction() { assertFalse(liveSummaryText.contains(LIVE_PRIVATE_INSERT_URI)); }\n', encoding='utf-8')
    (toolkit_test_dir / 'CryptaAppCliTest.java').write_text('void submissionCreate_whenInitializedStaticBundleIncludesSdk_expectAccepted() {} void assertCandidateStagingPendingSmoke() {} void assertInstallSmokePassed() {} String s = "vault.identities.manage operator-only";\n', encoding='utf-8')
    (toolkit_test_dir / 'LiveUskPublicationServiceTest.java').write_text('void publish_whenFakePublisherSucceeds_expectSanitizedSummaryAndRetainedStaging() {}\n', encoding='utf-8')
    (toolkit_test_dir / 'PublicationPlanWriterTest.java').write_text('void write_whenDryRun_expectPlan() {}\n', encoding='utf-8')
    (docs / DEVELOPER_BETA_TOOLKIT_DOC.name).write_text('crypta-app init --template hello-stable\ncrypta-app init --template queue-dashboard\ncrypta-app dev --bundle-dir .\ncrypta-app test --bundle-dir . --strict\ncrypta-app keys generate\ncrypta-app catalog entry\ncrypta-app publish-usk --dry-run\ncrypta-app publish-usk --live --private-insert-uri-env CRYPTAD_FIRST_PARTY_CATALOG_INSERT_URI --form-password-env CRYPTAD_CERT_FORM_PASSWORD\nThe private insert URI is secret, cryptad-app-catalog.signature is published at the same USK, and dry-run remains available.\n', encoding='utf-8')
    (workspace / APP_UI_DESIGN_SYSTEM_DOC).write_text('crypta-platform.js loads before app.js. Static apps load crypta-ui-tokens.css, crypta-ui.css, then app.css. Use cr-shell and cr-button classes. Content-Security-Policy includes connect-src. Accessibility requires aria labels. Permission disclosure mirrors app.permissions. Run crypta-app ui lint --bundle-dir. First-party Queue Manager, Publisher, Site Publisher, and Profile Publisher use this guidance. Warnings become failure in release-candidate evidence.\n', encoding='utf-8')
    sandbox_dir = workspace / 'platform-apphost/src/main/java/network/crypta/platform/apphost/sandbox'
    sandbox_test_dir = workspace / 'platform-apphost/src/test/java/network/crypta/platform/apphost/sandbox'
    sandbox_dir.mkdir(parents=True, exist_ok=True)
    sandbox_test_dir.mkdir(parents=True, exist_ok=True)
    (sandbox_dir / 'BubblewrapSandboxProvider.java').write_text('class BubblewrapSandboxProvider { static final String PROVIDER_NAME = "bubblewrap"; Object level = AppSandboxSupportLevel.ENFORCED; Object env = checkedContext.environment(); String docs = "path-free status"; }\n', encoding='utf-8')
    (sandbox_dir / 'BubblewrapCommandBuilder.java').write_text('class BubblewrapCommandBuilder { void command() { command.add("--die-with-parent"); command.add("--new-session"); command.add("--unshare-pid"); command.add("--unshare-ipc"); command.add("--ro-bind"); command.add("--bind"); command.add("--"); } }\n', encoding='utf-8')
    (sandbox_dir / 'BubblewrapAvailability.java').write_text('class BubblewrapAvailability { }\n', encoding='utf-8')
    (sandbox_dir / 'AppSandboxProviders.java').write_text('class AppSandboxProviders { BubblewrapSandboxProvider provider; }\n', encoding='utf-8')
    (sandbox_test_dir / 'BubblewrapSandboxProviderTest.java').write_text('class BubblewrapSandboxProviderTest { void prepareLaunch_whenContextContainsToken_expectCommandDoesNotExposeEnvironmentValues() { String commandText = "--die-with-parent --new-session --unshare-pid --unshare-ipc --ro-bind --bind CRYPTAD_APP_TOKEN"; assertFalse(commandText.contains("secret-token")); } }\n', encoding='utf-8')
    (sandbox_test_dir / 'AppSandboxProvidersTest.java').write_text('class AppSandboxProvidersTest { void providers_whenRequiredRestrictedProcessBubblewrapPreflightFails_expectFailClosed() {} void providers_whenRequiredRestrictedProcessBubblewrapUnavailable_expectFailClosed() {} String name = "PreflightFails RequiredRestrictedProcess expectFailClosed"; }\n', encoding='utf-8')
    apphost = workspace / 'platform-apphost/src/main/java/network/crypta/platform/apphost/runtime/LocalProcessAppHost.java'
    apphost.parent.mkdir(parents=True, exist_ok=True)
    uninstall_options = workspace / 'platform-apphost/src/main/java/network/crypta/platform/apphost/AppUninstallOptions.java'
    uninstall_options.parent.mkdir(parents=True, exist_ok=True)
    uninstall_options.write_text('record AppUninstallOptions(boolean preserveData) {}\n', encoding='utf-8')
    apphost.write_text('\nclass LocalProcessAppHost {\n  private static final String BASE_UNIX_PATH_ENTRIES = "/usr/bin:/bin";\n  private static final String TEMP_UPDATE_BACKUP_PREFIX = "app-install-backup-";\n  private static final String TEMP_ROLLBACK_BACKUP_PREFIX = "app-rollback-backup-";\n  InstalledAppSnapshot updateFromDirectory(String appId, Path stagedAppDirectory) throws IOException {\n    if (liveRunningProcess(normalizedAppId) != null) {\n      throw new AppHostException("cannot update a running app: " + normalizedAppId);\n    }\n    Path rollbackAppsDir = ensureRollbackAppsDirectory();\n    Path backupInstallRoot = temporaryManagedPath(installedAppsDir, TEMP_UPDATE_BACKUP_PREFIX + normalizedAppId + "-");\n    Path rollbackRoot = rollbackRootFor(normalizedAppId);\n    Path previousRollbackBackupRoot = temporaryManagedPath(rollbackAppsDir, TEMP_ROLLBACK_BACKUP_PREFIX + normalizedAppId + "-");\n    copyDirectoryTree(stagingRoot, temporaryInstallRoot);\n    verifyCopiedBundle(temporaryInstallRoot);\n    AppManifest manifest = validateCopiedBundle(temporaryInstallRoot);\n    requireMatchingUpdateTarget(normalizedAppId, manifest);\n    replaceInstalledBundle(paths.installedRoot(), temporaryInstallRoot, backupInstallRoot, rollbackRoot, previousRollbackBackupRoot);\n    cancelPendingRestartAfterAcceptedUpdate(normalizedAppId);\n    return new InstalledAppSnapshot(manifest, paths);\n  }\n  Optional<AppRollbackRecord> rollbackStatus(String appId) throws IOException {\n    return Optional.of(new AppRollbackRecord(appId));\n  }\n  InstalledAppSnapshot rollback(String appId) throws IOException {\n    if (liveRunningProcess(normalizedAppId) != null) {\n      throw new AppHostException("cannot rollback a running app: " + normalizedAppId);\n    }\n    Path rollbackRoot = rollbackRootFor(normalizedAppId);\n    Path currentInstallBackupRoot = temporaryManagedPath(installedAppsDir, TEMP_UPDATE_BACKUP_PREFIX + normalizedAppId + "-");\n    swapInstalledBundleWithRollback(paths.installedRoot(), rollbackRoot, currentInstallBackupRoot);\n    return new InstalledAppSnapshot(manifest, paths);\n  }\n  void uninstall(String appId, AppUninstallOptions options) {\n    if (!options.preserveData()) {\n      deleteAppData(appId);\n    }\n  }\n  void deleteAppData(String appId) {}\n  void populateEnvironment(Map<String, String> environment) {\n    environment.clear();\n    environment.put("PATH", safeUnixPath());\n    environment.put("CRYPTAD_APP_ID", "sample-app");\n    environment.put("CRYPTAD_APP_TOKEN", "token");\n    environment.put("CRYPTAD_APP_PERMISSIONS", "content.fetch");\n    environment.put("CRYPTAD_APP_UI_MODE", "static");\n  }\n  String safeUnixPath() { return BASE_UNIX_PATH_ENTRIES; }\n  private Path rollbackRootFor(String appId) { return layout.rollbackAppsDir().resolve(appId); }\n  private Path ensureRollbackAppsDirectory() { return layout.rollbackAppsDir(); }\n  private void replaceInstalledBundle(Path installedRoot, Path replacementRoot, Path backupRoot, Path rollbackRoot, Path previousRollbackBackupRoot) throws IOException {\n    moveIntoPlace(installedRoot, backupRoot);\n    try {\n      moveIntoPlace(replacementRoot, installedRoot);\n      moveIntoPlace(backupRoot, rollbackRoot);\n    } catch (IOException updateFailure) {\n      restoreInstalledBundle(installedRoot, backupRoot, updateFailure);\n      restorePreviousRollback(rollbackRoot, previousRollbackBackupRoot, true, updateFailure);\n      throw updateFailure;\n    }\n    deleteBackupAfterSuccessfulReplacement(previousRollbackBackupRoot, true);\n  }\n  private void swapInstalledBundleWithRollback(Path installedRoot, Path rollbackRoot, Path currentInstallBackupRoot) throws IOException {\n    moveIntoPlace(installedRoot, currentInstallBackupRoot);\n    moveIntoPlace(rollbackRoot, installedRoot);\n    moveIntoPlace(currentInstallBackupRoot, rollbackRoot);\n  }\n  private void deleteBackupAfterSuccessfulReplacement(Path backupRoot, boolean backupPresent) throws IOException {\n    throw new IOException("simulated backup cleanup failure");\n  }\n  private static void restoreInstalledBundle(Path installedRoot, Path backupRoot, IOException updateFailure) throws IOException {\n    moveIntoPlace(backupRoot, installedRoot);\n  }\n  private static void restorePreviousRollback(Path rollbackRoot, Path backupRoot, boolean backupPresent, IOException updateFailure) throws IOException {\n  }\n}\n', encoding='utf-8')
    apphost_test = workspace / 'platform-apphost/src/test/java/network/crypta/platform/apphost/runtime/LocalProcessAppHostTest.java'
    apphost_test.parent.mkdir(parents=True, exist_ok=True)
    apphost_test.write_text('\nclass LocalProcessAppHostTest {\n  void populateEnvironment_whenHostEnvironmentContainsSecrets_expectSanitizedChildEnvironment() {\n    String names = "JAVA_TOOL_OPTIONS LD_PRELOAD AWS_SECRET_ACCESS_KEY OPENAI_API_KEY SSH_AUTH_SOCK PRIVATE_KEY CRYPTAD_APPHOST_BWRAP";\n  }\n  void updateFromDirectory_whenInstalledStoppedApp_expectManifestAndExecutableReplacedPreservingMutableDirs() {\n    String data = "preserve-data.txt";\n    String cache = "preserve-cache.txt";\n    String run = "preserve-run.txt";\n  }\n  void updateFromDirectory_whenReplacingStoppedApp_expectPreviousBundleRecordedForRollback() {\n    AtomicInteger cleanupAttempts = new AtomicInteger();\n    LocalProcessAppHost host = allowUnsignedHost(_ -> {\n      cleanupAttempts.incrementAndGet();\n      throw new IOException("simulated backup cleanup failure");\n    });\n    Path firstUpdatedStage =\n        stageInstalledAppAt(tempDir.resolve(STAGE_UPDATE_DIR_NAME).resolve("first").resolve(SAMPLE_APP_ID));\n    InstalledAppSnapshot firstUpdate = host.updateFromDirectory(SAMPLE_APP_ID, firstUpdatedStage);\n    assertEquals(0, cleanupAttempts.get());\n    Path secondUpdatedStage =\n        stageInstalledAppAt(tempDir.resolve(STAGE_UPDATE_DIR_NAME).resolve("second").resolve(SAMPLE_APP_ID));\n    host.updateFromDirectory(SAMPLE_APP_ID, secondUpdatedStage);\n    assertEquals(\n        firstUpdate.manifest().appVersion(),\n        host.rollbackStatus(SAMPLE_APP_ID).orElseThrow().appVersion());\n    assertEquals(1, cleanupAttempts.get());\n  }\n  void rollback_whenPreviousBundleExists_expectRestoresBundleAndPreservesMutableDirs() {\n    String data = "rollback-data.txt";\n    String cache = "rollback-cache.txt";\n    String run = "rollback-run.txt";\n  }\n  void rollback_whenAppIsRunning_expectFailureAndInstalledBundleUnchanged() {}\n  void rollbackStatus_whenRecordExists_expectMetadataOmitsTokensAndHostPaths() {}\n}\n', encoding='utf-8')
    appupdates_dir = workspace / 'platform-api/src/main/java/network/crypta/platform/api/appupdates'
    appupdates_dir.mkdir(parents=True, exist_ok=True)
    (appupdates_dir / 'AppUpdatePolicyMode.java').write_text('\nenum AppUpdatePolicyMode {\n  MANUAL("manual"),\n  STAGE("stage"),\n  APPLY_WHEN_STOPPED("apply_when_stopped");\n}\n', encoding='utf-8')
    (appupdates_dir / 'AppUpdateCandidateStatus.java').write_text('\nenum AppUpdateCandidateStatus {\n  AVAILABLE("available"),\n  STAGED("staged"),\n  BLOCKED("blocked"),\n  INCOMPATIBLE("incompatible"),\n  AMBIGUOUS("ambiguous"),\n  ROLLBACK_AVAILABLE("rollback_available");\n}\n', encoding='utf-8')
    (appupdates_dir / 'AppUpdateCandidate.java').write_text('\nrecord AppUpdateCandidate() {\n  Map<String, Object> toJsonValue() {\n    json.put("channel", channel);\n    json.put("supportStatus", supportStatus);\n    json.put("securityAdvisories", securityAdvisories);\n    json.put("allowedChannels", allowedChannels);\n    json.put("review", review);\n    json.put("apiCompatibility", apiCompatibility);\n    json.put("permissionDelta", permissionDelta(candidatePermissions, installedPermissions));\n    json.put("dataMigration", dataMigration);\n    json.put("securityDecision", securityDecision);\n    json.put("blocksAutoUpdate", !eligibleForAutomaticStage());\n    return json;\n  }\n  Map<String, Object> securityDecision() { return securityDecision; }\n  boolean eligibleForAutomaticStage() { return materialConsentAllowsAutomaticStage(); }\n  boolean eligibleForAutomaticApply() { return !Boolean.TRUE.equals(securityDecision.get("blocksAutomaticApply")); }\n  boolean dataMigrationAllowsAutomaticStage() { return dataMigration.get("blockReason") == null; }\n  boolean materialConsentAllowsAutomaticStage() { return permissionDeltaAllowsAutomaticStage() && apiStabilityAllowsAutomaticStage() && securityAdvisoriesAllowAutomaticStage(); }\n  boolean materialConsentBlocksAutomaticStage() { return !materialConsentAllowsAutomaticStage(); }\n  boolean permissionDeltaAllowsAutomaticStage() { return true; }\n  boolean apiStabilityAllowsAutomaticStage() {\n    Object statusValue = apiCompatibility.get("status");\n    return statusValue instanceof String status && ("compatible".equals(status) || "satisfied".equals(status));\n  }\n  boolean securityAdvisoriesAllowAutomaticStage() { String reason = "security_advisory"; return securityAdvisories.isEmpty(); }\n  static Map<String, Object> reviewSummary(String status, String note) { return Map.of(); }\n  static Map<String, Object> permissionDelta(List<String> candidatePermissions, List<String> local) { return Map.of(); }\n}\n', encoding='utf-8')
    (appupdates_dir / 'AppDataMigrationPlan.java').write_text('\nrecord AppDataMigrationPlan() {\n  static final String STATUS_MISSING_MIGRATION = "missing_migration";\n\t  Map<String, Object> toJsonValue() {\n\t    json.put("dataMigration", this);\n\t    json.put("namespaces", namespaces);\n\t    json.put("blockReason", blockReason);\n\t    json.put("requiresStopped", requiresStopped);\n\t    return json;\n\t  }\n\t  record NamespaceStep(String namespace, int from, int to, String stepId, boolean rollbackCompatible, boolean requiresStopped) {}\n\t}\n', encoding='utf-8')
    (appupdates_dir / 'AppDataMigrationRunner.java').write_text('\n\tinterface AppDataMigrationRunner {\n\t  int MAX_CAPTURE_BYTES = 4096;\n\t  enum Mode { DRY_RUN, APPLY }\n\t\t  interface MigrationDataAccess {}\n\t\t  default void run(Path bundleRoot, AppDataMigrationPlan plan, Mode mode, MigrationDataAccess dataAccess) throws IOException {\n\t\t    ProcessBuilder builder = new ProcessBuilder(commandLine(command));\n\t\t    new AppEnv();\n\t\t    ProcessBoundary boundary = ProcessBoundary.detect(appEnv);\n\t\t    boundary.commandLine(command);\n\t\t    return unsupported();\n\t\t    String executable = "migration command is not executable";\n\t\t    String processGroups = "Process groups alone are not sufficient";\n\t\t    String blocker = "migration process containment is unavailable";\n\t\t    long timeout = OUTPUT_DRAIN_TIMEOUT_MILLIS;\n\t\t    builder.environment().clear();\n\t\t    builder.environment().put("CRYPTA_APP_MIGRATION_MODE", "dry-run");\n\t    builder.environment().put("CRYPTA_APP_MIGRATION_NAMESPACE", "feeds");\n    builder.environment().put("CRYPTA_APP_MIGRATION_INPUT", input.toString());\n    builder.environment().put("CRYPTA_APP_MIGRATION_OUTPUT", output.toString());\n  }\n\t}\n\t', encoding='utf-8')
    (appupdates_dir / 'AppUpdatePolicy.java').write_text('\nclass AppUpdatePolicy {\n  static final Set<AppCatalogChannel> DEFAULT_ALLOWED_CHANNELS = Set.of(AppCatalogChannel.STABLE);\n  boolean allowsAutomaticChannel(AppCatalogChannel channel) { return channel != AppCatalogChannel.DEPRECATED; }\n  Map<String, Object> toJsonValue() { json.put("allowedChannels", DEFAULT_ALLOWED_CHANNELS); return json; }\n}\n', encoding='utf-8')
    (appupdates_dir / 'AppUpdateService.java').write_text('\nclass AppUpdateService {\n  static final String ERROR_CHANNEL_POLICY_BLOCKED = "channel_policy_blocked";\n  static final String ERROR_CONSENT_REQUIRED = "consent_required";\n  static final String ERROR_APP_SECURITY_ACKNOWLEDGEMENT_REQUIRED = "app_security_acknowledgement_required";\n  static final String ERROR_APP_SECURITY_BLOCKED = "app_security_blocked";\n  static final String ERROR_APP_SECURITY_DENYLISTED = "app_security_denylisted";\n  static final String POLICY_SECURITY_DENYLIST_BLOCKED = "security_denylist_blocked";\n\t  static final String ERROR_APP_DATA_MIGRATION_MISSING = "app_data_migration_missing";\n\t  static final String ERROR_APP_DATA_MIGRATION_DRY_RUN_FAILED = "app_data_migration_dry_run_failed";\n\t  static final String ERROR_APP_DATA_MIGRATION_REVIEW_REQUIRED = "app_data_migration_review_required";\n\t  static final String ERROR_APP_DATA_MIGRATION_REQUIRES_STOPPED = "app_data_migration_requires_stopped";\n\t  static final String ERROR_APP_DATA_MIGRATION_SANDBOX_UNAVAILABLE = "app_data_migration_sandbox_unavailable";\n\t  AppUpdateService.SchedulerSummaryProvider schedulerSummaryProvider;\n\n  public synchronized Map<String, Object> check(String appId, boolean includeStaged) {\n    return summary(appId, installed);\n  }\n\n  public synchronized Map<String, Object> stage(String appId) {\n    AppUpdateCandidate candidate = candidateOrDetect(appId, installed);\n    requireSecurityGate(candidate.securityDecision(), securityAcknowledged);\n    AppCatalogInstallPlan plan = catalogManager.prepareInstallPlan(candidate.catalogId(), appId);\n    if (planDiffersFromCandidate(candidate, installed, plan)) {\n      throw new PlatformApiException(409, "update_candidate_changed", "changed");\n    }\n    AppDataMigrationPlan migrationPlan = buildMigrationPlan(appId, installed.manifest(), targetManifest);\n    boolean sandboxBlock =\n        targetManifest.sandboxPolicy().required()\n            && targetManifest.sandboxPolicy().mode() != AppSandboxMode.NONE;\n    if (migrationPlan.hasBlocker()) throw new PlatformApiException(409, ERROR_APP_DATA_MIGRATION_MISSING, "missing");\n\t    if (migrationPlan.operatorReviewRequired() && !migrationAcknowledged) {\n\t      throw new PlatformApiException(409, ERROR_APP_DATA_MIGRATION_REVIEW_REQUIRED, "review");\n\t    }\n\t    verifyStagedBundleBeforeStageDryRun(appId, candidate, plan);\n\t    migrationRunner.run(plan.stagedBundleDirectory(), migrationPlan, AppDataMigrationRunner.Mode.DRY_RUN, migrationDataAccess(appId, targetManifest));\n\t    if (!dryRunResult.success()) throw new PlatformApiException(409, ERROR_APP_DATA_MIGRATION_DRY_RUN_FAILED, "dry run");\n\t    bestMigrationPath(namespace, currentVersion, targetVersion, migrations);\n    stageCandidate(appId, installed, candidate);\n    stagedUpdates.put(appId, new StagedUpdate(candidate, plan, migrationPlan, Instant.now()));\n    return summary(appId, installed);\n  }\n\n  boolean planDiffersFromCandidate(AppUpdateCandidate candidate, InstalledAppSnapshot installed, AppCatalogInstallPlan plan) {\n    AppCatalogEntry entry = plan.entry();\n    return !candidate.securityDecision().equals(targetSecurityDecision(plan.catalogId(), entry).toJsonValue());\n  }\n\n\t\t  public synchronized Map<String, Object> apply(String appId, ApplyOptions options) {\n\t    requireCurrentStagedSecurityDecision(staged);\n\t    targetSecurityDecision(staged.candidate().catalogId(), staged.entry());\n\t    verifyStagedBundleBeforeApply(staged);\n\t    if (shouldHoldApplyMigrationWriteBarrier(targetManifest)) {\n\t      targetManifest.dataSchemaContract().declared();\n\t      beginUpdateMigrationWriteBarrier(normalizedAppId);\n\t    }\n\t    if (migrationPlan.required()) {\n\t      runApplyDryRunOrReject(staged, migrationPlan, targetManifest);\n\t      targetManifest.dataQuotaBytes();\n\t      verifyStagedBundleAfterApplyDryRun(staged);\n\t      beginUpdateMigrationWriteBarrier(normalizedAppId);\n\t      appDataSnapshot = createUpdateSnapshot(normalizedAppId);\n\t    }\n    InstalledAppSnapshot updated =\n        appHost.updateFromDirectory(normalizedAppId, staged.stagedBundleDirectory());\n    runApplyMigrationOrRollback(normalizedAppId, updated, migrationPlan, appDataSnapshot, healthFailureState);\n    rollbackAndRestoreSnapshot(normalizedAppId, healthFailureState, appDataSnapshot);\n\t    appDataService.restoreUpdateSnapshot(normalizedAppId, appDataSnapshot);\n\t    healthFailureState.markRollbackFailed();\n\t    closeUpdateMigrationWriteBarrier(barrier);\n\t    closeStage(normalizedAppId);\n\t    return summary(normalizedAppId, updated);\n\t  }\n\n\t\t  void verifyStagedBundleBeforeApply(StagedUpdate staged) {\n\t\t    catalogManager.verifyInstallPlan(staged.plan());\n\t\t  }\n\n\t  boolean shouldHoldApplyMigrationWriteBarrier(AppManifest targetManifest) {\n\t    return targetManifest.dataSchemaContract().declared();\n\t  }\n\n  void verifyStagedBundleBeforeStageDryRun(String appId, AppUpdateCandidate candidate, AppCatalogInstallPlan plan) {\n    catalogManager.verifyInstallPlan(plan);\n  }\n\n  boolean isAutomaticPolicyMigrationSkip(String errorCode) {\n    return ERROR_APP_DATA_MIGRATION_MISSING.equals(errorCode)\n        || ERROR_APP_DATA_MIGRATION_DRY_RUN_FAILED.equals(errorCode)\n        || ERROR_APP_DATA_MIGRATION_REVIEW_REQUIRED.equals(errorCode)\n        || ERROR_APP_DATA_MIGRATION_REQUIRES_STOPPED.equals(errorCode)\n        || ERROR_APP_DATA_MIGRATION_SANDBOX_UNAVAILABLE.equals(errorCode);\n  }\n\n\t  void recordMigrationDryRunFailure(String appId, AppUpdateCandidate candidate, AppDataMigrationPlan plan, String errorCode) {\n\t    if (ERROR_APP_DATA_MIGRATION_DRY_RUN_FAILED.equals(errorCode)) {\n\t      candidates.put(appId, candidateWithMigrationPlan(candidate, plan.withDryRunFailed()));\n\t    }\n  }\n\n\t\t  Map<String, Object> summary(String appId, InstalledAppSnapshot installed) {\n    json.put("scheduler", schedulerSummaryProvider.schedulerSummary(appId));\n    json.put("dataMigration", migrationPlan.toJsonValue());\n    json.put("installedSecurityDecision", installedSecurityDecision(appId, installed.manifest().appVersion()).toJsonValue());\n    if (productionMetadata.deprecatedForAutomaticUpdates()) {\n      throw new PlatformApiException(409, ERROR_CHANNEL_POLICY_BLOCKED, "blocked");\n    }\n    if (securityGateRequiresOperator(candidate.securityDecision())) {\n      appendSecurityGateHistory(appId, automaticAction(policy.mode()), candidate);\n    }\n    if (automaticSecurityGateFailureCode(candidate.securityDecision()).equals("security_denylist_blocked")) {\n      return json;\n    }\n    AppReviewReceiptVerifier.evaluate(entry, keys, policy, now);\n    return json;\n  }\n\n  void requireSecurityGate(Map<String, Object> securityDecision, boolean securityAcknowledged) {}\n  void requireCurrentStagedSecurityDecision(StagedUpdate staged) {}\n  Object targetSecurityDecision(String catalogId, AppCatalogEntry entry) {\n    return AppCatalogSecurityDecision.combine(\n        List.of(securityDecision(catalogId, entry), installedSecurityDecision(entry.appId(), entry.version())));\n  }\n  Object installedSecurityDecision(String appId, String version) { return null; }\n  boolean securityGateRequiresOperator(Map<String, Object> securityDecision) { return true; }\n  String automaticSecurityGateFailureCode(Map<String, Object> securityDecision) { return POLICY_SECURITY_DENYLIST_BLOCKED; }\n  String securityGateFailureCode(Map<String, Object> securityDecision) { return ERROR_APP_SECURITY_DENYLISTED; }\n  void appendSecurityGateHistory(String appId, String action, AppUpdateCandidate candidate) {\n    automaticSecurityGateFailureCode(candidate.securityDecision());\n  }\n  void appendMaterialConsentHistory(String appId, String action, AppUpdateCandidate candidate) {\n    appendHistory(appId, action, "failed", candidate.catalogId(), candidate.targetVersion(), ERROR_CONSENT_REQUIRED, "Policy skipped update because material consent is required.");\n  }\n\n  void closeMigrationScratch() {\n    try {\n      deleteRecursively(root);\n    } catch (IOException _) {\n      // Migration scratch cleanup is best effort; command success is reported separately.\n    }\n  }\n}\n', encoding='utf-8')
    (appupdates_dir / 'AppUpdateSchedulerConfig.java').write_text('\nclass AppUpdateSchedulerConfig {\n  static final String ENABLED_ENV = "CRYPTAD_APPUPDATES_SCHEDULER_ENABLED";\n  static final String APP_CHECK_INTERVAL_PROPERTY = "cryptad.appupdates.scheduler.appCheckIntervalSeconds";\n  static AppUpdateSchedulerConfig defaults() {\n    return new AppUpdateSchedulerConfig(\n        true,\n        Duration.ZERO,\n        Duration.ofSeconds(120),\n        Duration.ofSeconds(60),\n        Duration.ZERO,\n        Duration.ofSeconds(30),\n        Duration.ofSeconds(300));\n  }\n  static AppUpdateSchedulerConfig from(Map<?, ?> properties, Map<String, String> environment) {\n    return defaults();\n  }\n}\n', encoding='utf-8')
    (appupdates_dir / 'AppUpdateSchedulerState.java').write_text('\nclass AppUpdateSchedulerState {\n  Map<String, Object> toJsonValue() {\n    json.put("lastCheckAt", lastCheckAt);\n    json.put("nextCheckAt", nextCheckAt);\n    json.put("failureCount", failureCount);\n    json.put("lastErrorCode", lastErrorCode);\n    json.put("concurrency", "per-app-serialized");\n    return json;\n  }\n  // catalog scratch paths and staged bundle path values are never exposed here.\n}\n', encoding='utf-8')
    (appupdates_dir / 'FileAppUpdateSchedulerStore.java').write_text('\npublic final class FileAppUpdateSchedulerStore {\n  void write(Path source, Path target) throws IOException {\n    Files.move(source, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);\n  }\n}\n', encoding='utf-8')
    (appupdates_dir / 'AppUpdateScheduler.java').write_text('\npublic final class AppUpdateScheduler {\n  private final AppUpdateSchedulerConfig config;\n  private final AppUpdateSchedulerStore store;\n  private final AtomicBoolean running = new AtomicBoolean();\n  private static final String ERROR_CATALOG_REFRESH_FAILED = "catalog_refresh_failed";\n  private static final String MESSAGE_CATALOG_REFRESH_FAILED =\n      "Scheduler catalog refresh failed; cached verified catalogs remain in use.";\n  private static final String MESSAGE_APP_CHECK_FAILED = "Scheduler update check failed.";\n  // Manual remains the default; the scheduler discovers candidates and refreshes live USK catalog sources.\n  AppUpdateSchedulerTickResult tick(Instant now) {\n    if (!running.compareAndSet(false, true)) {\n      return AppUpdateSchedulerTickResult.alreadyRunning(now);\n    }\n    for (AppCatalogSourceSnapshot catalog : catalogManager.listCatalogs()) {\n      catalogManager.refresh(catalog.catalogId());\n    }\n    updateService.check(state.appId(), false);\n    return result;\n  }\n}\n', encoding='utf-8')
    (appupdates_dir / 'AppUpdatesApiHandler.java').write_text('\nclass AppUpdatesApiHandler {\n  static final String PARAM_SECURITY_ACKNOWLEDGED = "securityAcknowledged";\n  public Map<String, Object> stage(String appId) {\n    return updateService.stage(appId);\n  }\n\n  public Map<String, Object> stage(String appId, Map<String, List<String>> queryParameters) {\n    boolean migrationAcknowledged = true;\n    boolean securityAcknowledged = true;\n    return updateService.stage(appId, reviewAcknowledged, securityAcknowledged, migrationAcknowledged);\n  }\n\n  public Map<String, Object> apply(String appId, Map<String, List<String>> queryParameters) {\n    return updateService.apply(appId, applyOptions(queryParameters));\n  }\n}\n', encoding='utf-8')
    appupdates_test_dir = workspace / 'platform-api/src/test/java/network/crypta/platform/api/appupdates'
    appupdates_test_dir.mkdir(parents=True, exist_ok=True)
    (appupdates_test_dir / 'AppUpdateServiceTest.java').write_text('\nclass AppUpdateServiceTest {\n  void apply_whenAppStartsAfterPrecheck_expectConflictNotServerError() {\n    when(appHost.updateFromDirectory(APP_ID, plan.stagedBundleDirectory()))\n        .thenThrow(new AppHostException("cannot update a running app: " + APP_ID));\n    assertEquals("app_running", exception.errorCode());\n  }\n\t\t  void stage_whenSchemaIncreaseHasNoMigrationStep_expectBlockedBeforeBundleReplacement() {}\n\t\t\t  void apply_whenMigrationRequiredAndRunnerPasses_expectSnapshotApplyAndSchemaMetadata() {}\n\t\t\t  void apply_whenAppDataWriteAttemptsDuringMigrationWindow_expectWriteRejectedAndBarrierReleased() {}\n\t\t\t  void apply_whenAppDataWriteAttemptsDuringFinalMigrationDryRun_expectWriteRejected() {}\n\t\t\t  void apply_whenStagedMigrationBundleVerificationFails_expectDryRunBlockedBeforeRunner() {}\n\t\t\t  void apply_whenMigrationDryRunMutatesStagedBundle_expectReverifiedBeforeInstall() {}\n\t\t\t  void stage_whenTargetManifestRaisesDataQuota_expectDryRunUsesTargetQuota() {}\n\t\t  void apply_whenChainedMigrationRunner_expectEachStepAppliedBeforeNextStep() {}\n\t\t  void apply_whenMigrationContractHasNoExistingDataAndWriteAppearsBeforeReplacement_expectWriteRejected() {}\n\t\t  void apply_whenMigrationApplyFailsAndBundleRollbackFails_expectMigrationFailurePreserved() {}\n\t\t  void stage_whenMigrationRollbackIncompatibleWithoutAcknowledgement_expectReviewRequired() {}\n\t\t\t  void stage_whenStoppedRequiredMigrationAndAppRunning_expectBlockedBeforeDryRun() {}\n\t\t\t  void check_whenStagePolicyMigrationPathMissing_expectCandidateSummaryWithoutCheckFailure() {}\n\t\t\t  void check_whenStagePolicyMigrationDryRunFails_expectCandidateSummaryWithoutCheckFailure() {}\n\t\t\t  void check_whenStagePolicyMigrationDryRunThrows_expectCandidateSummaryWithoutCheckFailure() {}\n\t\t\t  void check_whenApplyWhenStoppedPolicyMigrationDryRunFails_expectCandidateSummaryWithoutApply() {}\n\t\t\t  void stage_whenMigrationBundleRequestsOptionalSandbox_expectDryRunAndStage() {}\n\t\t  void check_whenApplyWhenStoppedPolicySandboxMigration_expectCandidateSummaryWithoutApply() {}\n\t\t  void check_whenStagePolicyCandidateAddsPermission_expectConsentRequiredHistory() {}\n\t\t  void check_whenStagePolicyCandidateHasSecurityAdvisory_expectConsentRequiredHistory() {}\n\t\t  void check_whenStagePolicyMigrationRollbackIncompatible_expectCandidateRequiresOperatorReview() {}\n\t\t  void previewForConsent_whenMigrationRollbackIncompatible_expectCandidateRequiresOperatorReview() {}\n\t\t  void check_whenCatalogSecurityDecisionWarns_expectCandidateIncludesSecurityDecision() {}\n\t\t  void stage_whenSecurityWarningIsNotAcknowledged_expectStableSecurityAckError() {}\n\t\t  void stage_whenSecurityDecisionIsDenylisted_expectStableSecurityError() {}\n\t\t  void stage_whenStagedMigrationBundleVerificationFails_expectDryRunBlockedBeforeRunner() {}\n\t\t  void stage_whenMigrationHasDeadEndBranch_expectCompletePathSelected() {}\n\t  void stage_whenCompatibleChainCompetesWithIncompatibleDirectStep_expectCompatiblePathSelected() {}\n\t}\n\t', encoding='utf-8')
    (appupdates_test_dir / 'AppDataMigrationRunnerTest.java').write_text('class AppDataMigrationRunnerTest { void run_whenOnlyProcessGroupCleanupCouldBeBypassed_expectFailsClosedBeforeCommand() {} void run_whenProcessBoundaryUnavailable_expectFailsClosedBeforeCommand() {} void run_whenMigrationCommandIsNotExecutable_expectFailsBeforeCompletion() {} }\n', encoding='utf-8')
    (appupdates_test_dir / 'AppUpdateSchedulerConfigTest.java').write_text('\nclass AppUpdateSchedulerConfigTest {\n  void from_whenValuesMalformed_expectDefaultsRetained() {}\n}\n', encoding='utf-8')
    (appupdates_test_dir / 'AppUpdateSchedulerTest.java').write_text('\nclass AppUpdateSchedulerTest {\n  void tick_whenCatalogAndAppAreDue_expectRefreshOnceThenDelegatesCheck() {\n    Object order = inOrder(catalogManager, updateService);\n  }\n  void tick_whenManualPolicy_expectCheckOnlyAndNoStageOrApply() {\n    verify(catalogManager, never()).prepareInstallPlan(eq(CATALOG_ID), eq(APP_ID));\n    verify(appHost, never()).updateFromDirectory(eq(APP_ID), eq(tempDir));\n  }\n  void tick_whenStagePolicy_expectVerifiedCandidateStagedByServicePolicy() {}\n  void tick_whenApplyWhenStoppedPolicy_expectStoppedAppAppliedByServicePolicy() {}\n  void tick_whenApplyWhenStoppedPolicyAndAppRunning_expectRunningAppNotStoppedOrUpdated() {\n    String message = "Policy skipped apply because the app is running.";\n  }\n  void tick_whenCheckFails_expectSanitizedFailureAndBackoff() {}\n  void tick_whenCatalogRefreshFails_expectFailureContainedAndAppsStillChecked() {}\n  void summary_whenSchedulerStatePresent_expectPathFreeSchedulerSummary() {\n    String token = "secret-token";\n    assertFalse(summary.toString().contains(tempDir.toString()));\n  }\n}\n', encoding='utf-8')
    runtime_source = workspace / 'bridge-http-runtime/src/main/java/network/crypta/clients/http/bridge/CoreHttpShellRuntimeSupport.java'
    runtime_source.parent.mkdir(parents=True, exist_ok=True)
    runtime_source.write_text('\nclass CoreHttpShellRuntimeSupport {\n  AppUpdateScheduler createAppUpdateScheduler() {\n    return new AppUpdateScheduler(layout.dataDir().resolve("apps").resolve("update-scheduler"));\n  }\n  ContentSubscriptionService contentSubscriptionService() { return contentSubscriptionService; }\n  ContentSubscriptionService createContentSubscriptionService() {\n    return new ContentSubscriptionService(\n      new FileContentSubscriptionStore(layout.dataDir().resolve("apps").resolve("content-subscriptions")));\n  }\n  AppDataService createAppDataService() {\n    return new AppDataService(\n      new FileAppDataStore(layout.dataDir().resolve("apps").resolve("durable-app-data")),\n      appHost, config, true);\n  }\n  TrustGraphApiHandler createTrustGraphApiHandler() {\n    return new TrustGraphApiHandler(\n      new FileTrustGraphStore(layout.dataDir().resolve("apps").resolve("trust-graph")));\n  }\n  AppServiceCoordinator createAppServiceCoordinator() {\n    return new AppServiceCoordinator(\n      new FileAppServiceGrantStore(layout.dataDir().resolve("apps").resolve("app-services")),\n      new TrustGraphScoreAppServiceAdapter(createTrustGraphApiHandler()));\n  }\n  ContentSubscriptionScheduler createContentSubscriptionScheduler() {\n    return new ContentSubscriptionScheduler(contentSubscriptionService);\n  }\n  void wire() {\n    appUpdateService.setSchedulerSummaryProvider(appUpdateScheduler::summary);\n    appUpdateScheduler.start();\n    contentSubscriptionScheduler.start();\n  }\n  Thread createAppUpdateSchedulerShutdownJob() { return new Thread(appUpdateScheduler::close); }\n  Thread createContentSubscriptionSchedulerShutdownJob() {\n    return new Thread(contentSubscriptionScheduler::close);\n  }\n}\n', encoding='utf-8')
    web_shell = workspace / 'platform-web-shell/src/main/resources/network/crypta/platform/webshell/static/web-shell.js'
    web_shell.parent.mkdir(parents=True, exist_ok=True)
    web_shell.write_text('\nfunction renderRecommendedCatalogs(){}\nfunction renderRecommendedCatalogCard(){}\nconst legacySecurityLevelsPath = normalizeLocalPath(bootstrap.legacySecurityLevelsPath, "/seclevels/");\nconst legacyDiagnosticPath = normalizeLocalPath(bootstrap.legacyDiagnosticPath, null);\nconst legacySecurityLevelsFallbackPath = legacySecurityLevelsPath + "?legacyFallback=security-levels";\nconst legacyDiagnosticExportFallbackPath = legacyDiagnosticPath + "?legacyFallback=diagnostic-export";\nconst recommendedCatalogPath = "app-catalogs/recommended";\nconst recommendedCatalogAction = "addRecommended";\nconst catalogChannelSelect = "catalog-channel-select";\nfunction catalogAppChannel(app){}\nfunction securityAdvisoryListNode(values){}\nfunction catalogMaintenancePolicyNode(app){ return "Maintenance policy"; }\nfunction catalogMaintenanceDeclared(maintenance){}\nconst deprecatedCatalogClass = "is-deprecated-channel";\nfunction appServiceGrantPath(){}\nfunction setSecurityLegacyFallbackStatus(){ return "Open the legacy security page"; }\nfunction renderSecurityLegacyFallbackAction(){ return "Open legacy password and recovery forms"; }\nfunction configureDiagnosticLegacyExportAction(){ return "Open legacy plaintext diagnostic export support fallback emergency"; }\nsections.security.append(renderSecurityLegacyFallbackAction());\nconst appServiceTitle = "App-service grants";\nconst approve = "Approve";\nconst revoke = "Revoke";\nconst renewBundle = "Renew bundle";\nconst safeSubjectHash = "subjectUriHash";\nfunction renderAppServiceDependencyGraph(graph){}\nfunction renderAppServiceBundleCard(bundle){}\napiUrl("app-services");\napiUrl("app-services/grants");\napiUrl("app-services/dependencies");\napiUrl("app-services/grant-bundles");\napiUrl("app-services/audit?limit=12");\nfunction registeredAppUiOrigin(app){ return "http://127.0.0.1:1234"; }\nfunction safeSameOriginAppUiHref(url, allowIsolatedLaunchParameter){ return "/apps/demo/"; }\nfunction normalizeLaunchFallbackHref(value){}\nfunction normalizeIsolatedLaunchHref(value){}\nfunction normalizeIsolatedProbeHref(value, expectedOrigin){}\nconst originPolicy = \'url.username url.password url.search !== "" url.hash !== "" /apps/\';\nfetch("/.well-known/cryptad-origin.json", { credentials: "omit", mode: "cors" });\ndefinitionList([\n  ["Scheduler status", scheduler.status],\n  ["Scheduler failures", scheduler.failureCount],\n  ["Last scheduler error", scheduler.lastErrorCode],\n  ["App-data migration blocker", migrationBlockerSummary(dataMigration)],\n]);\nconst migrationTitle = "App-data migration plan";\nconst migrationAcknowledged = "migrationAcknowledged";\nconst migrationStepList = "migration-step-list";\nconst storedCatalogChannel = window.localStorage.getItem("catalogChannel");\nfunction downloadAllAppDataBackup(){ return postForm("operator/app-data/backups", new FormData()); }\nfunction submitAppDataRestoreForm(form, restoreAction, statusSetter){}\nfunction setBetaDashboardStatus(message){}\nfunction downloadJsonBlob(value, fileName){ new Blob([`${formatJson(value)}\\n`]); }\nfunction urlSafeBase64ToBytes(value){ return value; }\nfunction appDataBackupPayloadBlob(response){ const payloadBase64 = response.payloadBase64; return new Blob([urlSafeBase64ToBytes(payloadBase64)]); }\nfunction downloadAppDataBackupPayload(response, fallbackScope, appId){ downloadBlob(appDataBackupPayloadBlob(response)); }\ndownloadAppDataBackupPayload(response, "all-apps", "");\ndownloadAppDataBackupPayload(response, "single-app", appId);\nfunction appDataBackupFormDataForApp(appId){ const formData = new FormData(); formData.set("appId", appId); return formData; }\nfunction allAppDataBackupFormData(){ const formData = new FormData(); formData.set("scope", "all"); return formData; }\napiUrl("operator/app-data/restore/plan");\napiUrl("operator/app-data/restore");\nconst appDataRestoreFields = "payloadBase64 replaceNamespace replaceApp backupPayload Export backup before delete";\n', encoding='utf-8')
    web_shell.write_text(web_shell.read_text(encoding='utf-8') + '\nlet betaDashboardLoadGeneration = 0;\nlet supportBundleSnapshot = null;\nlet supportBundlePreviewSnapshot = null;\nfunction renderBetaDashboard(data){}\nfunction renderSecurityResponseSummary(response){ return "Production security response Security response Denylisted app versions Support handling"; }\nfunction securityResponseTone(status){}\nfunction renderSecurityResponseActionLabels(actions){}\nfunction renderSecurityResponseRecordCard(title, records, lineFormatter){}\nfunction securityResponseAdvisoryLine(advisory){}\nfunction securityResponseDenylistLine(denylistEntry){}\nfunction securityResponseCatalogKeyLine(catalogKey){}\nfunction renderBetaCatalogs(catalogs){}\nfunction renderBetaApps(apps){}\nfunction renderBetaSubscriptions(subscriptions){}\nfunction renderBetaTrustAndServices(trustGraph, appServices){}\nconst trustPreviewTitle = "Trust Graph Local RC";\nconst trustScopeText = "Local trust only; it is not global truth, not moderation, not blocking, "\n  + "not routing policy, no legacy WoT, no global moderation, and no crawling.";\nconst trustScopeFields = "scope statementLifecycle localAnchorsOnly importedStatementsOnly "\n  + "noCrawling noGlobalModeration noBlocking noRoutingDecisions noLegacyWoTCompatibility";\nfunction renderBetaRecoveryActions(actions){}\nfunction operatorRecoveryActionVisible(action){ const actionId = "preserve-data-uninstall"; return actionId !== "preserve-data-uninstall"; }\nfunction loadBetaDashboardSection(){ loadJson(apiUrl("operator/beta-dashboard")); }\nfunction loadSupportBundle(){ loadJson(apiUrl("operator/support-bundle/preview")); loadJson(apiUrl("operator/support-bundle")); supportBundleSnapshot = {}; }\nfunction supportBundleRedactionStatus(bundle){ return "pass"; }\nfunction supportBundleRedactionFailed(bundle){ return false; }\nfunction supportBundleExportBlocked(bundle){ return supportBundleRedactionFailed(bundle); }\nfunction supportBundleOmittedFieldCount(bundle){ return 0; }\nfunction supportBundleDigestShort(bundle){ return "0123456789abcdef..."; }\nfunction supportJsonText(bundle){ return formatJson(bundle); }\nconst supportBundleBlocked = "Support bundle redaction failed; copy and download are disabled.";\nfunction downloadSupportBundle(){}\nfunction copySupportSummary(){ return "Support JSON copied."; }\nfunction submitOperatorRecoveryAction(form){}\nsections.betaDashboard.addEventListener("submit", async () => submitOperatorRecoveryAction(form));\nfunction renderOperatorRcRecovery(){}\nfunction loadOperatorRcDashboard(){ loadJson(apiUrl("operator/rc-dashboard")); rcCompatibilityFallback = true; }\nfunction previewOperatorSupportBundle(){ loadJson(apiUrl("operator/support-bundle/preview")); supportBundlePreviewSnapshot = {}; }\nfunction buildOperatorRcRecoveryAction(action){ operatorRcSubmitButton("Plan", "plan", false); operatorRcSubmitButton("Execute", "execute", action.destructive === true); }\nfunction operatorRcSubmitButton(label, action, destructive){}\nfunction submitOperatorRcRecoveryAction(form){\n  const planTokenInput = document.createElement("input");\n  planTokenInput.name = "planToken";\n  const planToken = typeof plan.planToken === "string" ? plan.planToken : "";\n  return postForm("operator/recovery/plan", new FormData());\n}\nfunction executeOperatorRcRecoveryAction(form){\n  const planTokenInput = form.querySelector(\'input[name="planToken"]\');\n  return postForm("operator/recovery/execute", new FormData());\n}\nfunction renderOperatorRcPlan(container, plan){}\nfunction renderOperatorRcResult(container, result){ appendOperatorRcResultSteps(container, result.steps); appendOperatorRcResultDetails(container, result.details); appendOperatorRcSupportBundleArtifact(container, result); }\nfunction appendOperatorRcResultSteps(container, steps){}\nfunction appendOperatorRcResultDetails(container, details){}\nfunction appendOperatorRcSupportBundleArtifact(container, result){ downloadJsonBlob(supportBundle, supportBundleFileName(supportBundle)); }\nfunction operatorRcBoundedScalar(value){ return value; }\nfunction operatorRcResultPreservesVisibleArtifact(result){ switch (result.actionId) { case "network-budget.view": case "support-bundle.export": case "trust-graph.export-summary": return true; default: return false; } }\nfunction operatorRcResultShouldReload(result){ return !operatorRcResultPreservesVisibleArtifact(result); }\nconst quotaText = ["Quota warnings", "Data quota"];\nconst quotaCheck = "quota.dataOverLimit || quota.cacheOverLimit";\nfunction text(value){ return document.createTextNode(value); }\nfunction securityDecisionNoticeNode(securityDecision, installed){ text("Safe uninstall guidance"); }\nfunction catalogSecurityDetailsNode(app){ definitionList([["Safe uninstall guidance", app.safeUninstallGuidance]]); }\nfunction appendSecurityAcknowledgement(form, securityDecision, action){ const input = document.createElement("input"); input.name = "securityAcknowledged"; input.className = "security-acknowledgement"; form.append(input); }\nfunction securityDecisionActionReason(app){ return "app-card-actions"; }\nconst installedSecurityWarning = "Installed version vulnerable";\nconst safeSecurityDom = "definitionList text safeUninstallGuidance";\n', encoding='utf-8')
    web_shell_index = workspace / 'platform-web-shell/src/main/resources/network/crypta/platform/webshell/static/index.html'
    web_shell_index.write_text('<article id="beta-dashboard"><h2>Operator RC Recovery</h2><p>The beta dashboard route remains a compatibility fallback.</p><div id="beta-dashboard-body"></div><a id="diagnostics-legacy-export-link">Open legacy plaintext diagnostic export</a><p>Plaintext diagnostics remain only as support or emergency fallback.</p><p>This support bundle is generated locally and is not uploaded automatically. It excludes raw content, raw app data, private insert URIs, tokens, identity material, and local paths. Review it before sharing.</p><button id="support-bundle-download-button">Download support JSON</button><button id="support-bundle-copy-button">Copy support JSON</button><button id="all-app-data-backup-button">Download all app-data backup</button><form id="operator-app-data-restore-form"><label>Sensitive backup payload</label><textarea name="backupPayload"></textarea></form></article>\n', encoding='utf-8')
    web_shell_test.write_text(web_shell_test.read_text(encoding='utf-8') + 'void assertBetaDashboardMarkersPresent(String script) {} void assertBetaDashboardLoadSequencing(String script) {} void assertAppDataBackupRestoreMarkersPresent(String script) {} void assertSecurityMarkersPresent(String script) { String s = "function appendSecurityAcknowledgement(form, securityDecision, action) input.name = \\"securityAcknowledged\\";"; } void assertOperatorRcRecoveryMarkersPresent(String script) { String s = "loadJson(apiUrl(\\"operator/rc-dashboard\\")) loadJson(apiUrl(\\"operator/support-bundle/preview\\")) Operator RC recovery actions unavailable in read-only mode."; } void calls() { assertBetaDashboardMarkersPresent(script); assertBetaDashboardLoadSequencing(script); assertAppDataBackupRestoreMarkersPresent(script); assertOperatorRcRecoveryMarkersPresent(script); }\n', encoding='utf-8')
    operator_dir = api_dir / 'operator'
    operator_dir.mkdir(parents=True, exist_ok=True)
    (operator_dir / 'OperatorBetaDashboardService.java').write_text('\nfinal class OperatorBetaDashboardService {\n  Map<String, Object> dashboard() {\n    dashboard.put("overallStatus", status);\n    dashboard.put("summary", summary);\n    dashboard.put("catalogs", catalogs);\n    dashboard.put("apps", apps);\n    dashboard.put("subscriptions", subscriptions);\n    dashboard.put("trustGraph", trustGraph);\n    dashboard.put("appServices", appServices);\n    dashboard.put("securityResponse", securityResponse);\n    dashboard.put("installedSecurityDecision", installedSecurityDecision);\n    dashboard.put("legacyAdmin", legacyAdmin);\n    dashboard.put("diagnostics", diagnostics);\n    dashboard.put("recoveryActions", actions);\n    return dashboard;\n  }\n  Map<String, Object> supportBundle() {\n    OperatorSupportRedactor.redact(dashboard);\n    OperatorSupportRedactor.redact(diagnostics);\n    OperatorSupportRedactor.redact(recentAudit);\n    OperatorSupportRedactor.redact(sections);\n    int SUPPORT_BUNDLE_SCHEMA_VERSION = 2;\n    bundle.put("kind", "cryptad-operator-support-bundle");\n    bundle.put("schemaVersion", SUPPORT_BUNDLE_SCHEMA_VERSION);\n    bundle.put("supportDigest", supportDigestForPayload(bundle));\n    bundle.put("privacy", Map.of("includesRawContent", false, "includesRawAppData", false,\n      "includesPrivateInsertUris", false, "includesTokens", false,\n      "includesIdentityMaterial", false, "includesLocalPaths", false,\n      "localOnlyUntilExported", true));\n    bundle.put("redaction", Map.of("omittedFieldNames", List.of(), "omittedFieldCount", 0,\n      "redactionFindings", List.of(), "rawSensitiveMaterialExcluded", true,\n      "patternsChecked", OperatorSupportRedactor.patternsChecked()));\n    bundle.put("sections", Map.of("catalog", catalog, "appUpdates", updates,\n      "subscriptions", subscriptions, "appData", appData, "appServiceGrants", grants,\n      "consent", consent, "migrations", migrations, "sandbox", sandbox,\n      "contentFormats", contentFormats, "trustGraph", trustGraph, "socialInbox", socialInbox,\n      "recovery", recovery, "diagnostics", diagnostics, "legacyFallbacks", legacyFallbacks,\n      "releaseCertification", releaseCertification));\n    bundle.put("rawDiagnosticBodiesExcluded", true);\n    bundle.put("plainTextExportEmbeddedInDefaultBundle", false);\n    String safe = "\\"rawDiagnosticBodiesExcluded\\" \\"plainTextExportEmbeddedInDefaultBundle\\" "\n      + "app-platform.privacy-preserving-beta-diagnostics";\n    diagnosticsApiHandler.supportSummary();\n    return bundle;\n  }\n  Object supportDigestForPayload(Map<String, Object> supportBundlePayload) { return "sha256"; }\n  Map<String, Object> catalogSummary(Map<String, Object> catalog) {\n    json.put("trustedCatalogKeyStatus", "configured");\n    json.put("lastFetchStatus", status);\n    json.put("recommendedFirstPartyPresent", true);\n    safeSourceDisplay(source, sourceKind);\n    action("refresh-catalog", "Refresh catalog", "POST", "app-catalogs/" + encodePathSegment(catalogId) + "/refresh", true);\n    return json;\n  }\n  void appRecoveryActions() {\n    action("check-app-update", "", "POST", "", true);\n    action("stage-app-update", "", "POST", "", true);\n    action("apply-app-update", "", "POST", "", true);\n    action("rollback-app", "", "POST", "", true);\n    action("open-app-logs", "", "GET", "", true);\n    action("preserve-data-uninstall", "", "DELETE", "", true);\n  }\n  void subscriptionRecoveryActions() {\n    String base = "operator/subscriptions/";\n    action("refresh-subscription", "", "POST", base + "/refresh", true);\n    action("pause-subscription", "", "POST", base + "/pause", true);\n    action("resume-subscription", "", "POST", base + "/resume", true);\n    action("reset-subscription-backoff", "", "POST", base + "/reset-backoff", true);\n    action("reschedule-subscription-now", "", "POST", base + "/reschedule-now", true);\n  }\n  void trustGraphSummary() {\n    json.put("previewOnly", true);\n    json.put("completeWot", false);\n    json.put("scope", scope);\n    json.put("statementLifecycle", statementLifecycle);\n    String warning = "Trust Graph Local RC is local operator-curated state only, not global truth, moderation, blocking, routing policy, or legacy Web of Trust compatibility.";\n  }\n  void appSummary(String appId) {\n    appDataSummary(appId);\n    json.put("appData", appData);\n    String apphost = "apphost_quota_over_limit";\n    String appData = "app_data_quota_unavailable";\n    json.put("quotaWarningCount", 1);\n    json.put("reviewTrust", reviewTrust);\n  }\n}\n', encoding='utf-8')
    recovery_dir = operator_dir / 'recovery'
    recovery_dir.mkdir(parents=True, exist_ok=True)
    (recovery_dir / 'OperatorRecoveryActionId.java').write_text('\nenum OperatorRecoveryActionId {\n  CATALOG_REFRESH("catalog.refresh"),\n  CATALOG_REVERIFY("catalog.reverify"),\n  CATALOG_REPAIR_FIRST_PARTY_SOURCE("catalog.repair-first-party-source"),\n  APP_CHECK_UPDATE("app.check-update"),\n  APP_STAGE_UPDATE("app.stage-update"),\n  APP_APPLY_UPDATE("app.apply-update"),\n  APP_ROLLBACK("app.rollback"),\n  APP_REINSTALL_FROM_CATALOG("app.reinstall-from-catalog"),\n  APP_EXPORT_BEFORE_UNINSTALL("app.export-before-uninstall"),\n  APP_STOP("app.stop"),\n  APP_START("app.start"),\n  SUBSCRIPTION_REFRESH("subscription.refresh"),\n  SUBSCRIPTION_PAUSE("subscription.pause"),\n  SUBSCRIPTION_RESUME("subscription.resume"),\n  SUBSCRIPTION_RESET_BACKOFF("subscription.reset-backoff"),\n  SUBSCRIPTION_RESCHEDULE_NOW("subscription.reschedule-now"),\n  SUBSCRIPTION_DELETE("subscription.delete"),\n  APP_SERVICE_GRANT_REVOKE("app-service.grant-revoke"),\n  APP_SERVICE_BUNDLE_RENEW("app-service.bundle-renew"),\n  APP_SERVICE_BUNDLE_REVALIDATE("app-service.bundle-revalidate"),\n  APP_SERVICE_BUNDLE_REJECT("app-service.bundle-reject"),\n  TRUST_GRAPH_EXPORT_SUMMARY("trust-graph.export-summary"),\n  TRUST_GRAPH_RESET_LOCAL_STATE("trust-graph.reset-local-state"),\n  TRUST_GRAPH_CLEAR_AUDIT("trust-graph.clear-audit"),\n  TRUST_GRAPH_RECOMPUTE_SUMMARY("trust-graph.recompute-summary"),\n  NETWORK_BUDGET_VIEW("network-budget.view"),\n  SUPPORT_BUNDLE_PREVIEW("support-bundle.preview"),\n  SUPPORT_BUNDLE_EXPORT("support-bundle.export");\n  static OperatorRecoveryActionId fromJsonValue(String value) { return CATALOG_REFRESH; }\n  OperatorRecoveryActionId(String value) {}\n}\n', encoding='utf-8')
    (recovery_dir / 'OperatorRecoveryService.java').write_text('\nfinal class OperatorRecoveryService {\n  private static final String PARAM_PLAN_TOKEN = "planToken";\n  OperatorRecoveryPlan plan() { return null; }\n  OperatorRecoveryResult result() { return null; }\n  String issuePlanToken() { return PARAM_PLAN_TOKEN; }\n  String requireIssuedPlanToken() {\n    String required = "recovery_plan_required";\n    String mismatch = "recovery_plan_mismatch";\n    return required + mismatch;\n  }\n  Object executePlanned(OperatorRecoveryPlan plan) {\n    OperatorRecoveryActionId action = OperatorRecoveryActionId.fromJsonValue("");\n    switch (action) { default: throw new IllegalArgumentException("unknown_recovery_action"); }\n  }\n  void catalogRecovery(OperatorRecoveryTarget target) {\n    appCatalogsApiHandler.refresh(target.catalogId());\n    appCatalogsApiHandler.addRecommended(target.catalogId());\n    reverifiedCatalog(target.catalogId());\n  }\n  void appRecovery(OperatorRecoveryTarget target) {\n    appUpdateService.rollback(target.appId(), false);\n    String unavailable = "A dedicated verified catalog reinstall API is not available.";\n    String running = "App must be stopped before rollback.";\n    appDataService.exportBackup(target.appId(), currentCryptaVersion.get());\n    appsApiHandler.uninstall(target.appId(), false, true);\n    Object uninstallFailure = "uninstallFailure";\n    clearAppStateAfterRecoveryUninstall(target.appId());\n    partialExportBeforeUninstallResult();\n  }\n  Object partialExportBeforeUninstallResult() { return "partial sensitiveBackup"; }\n  boolean requiresStoppedApp(OperatorRecoveryActionId actionId) {\n    return actionId == OperatorRecoveryActionId.APP_START;\n  }\n  void grantRecovery() {\n    appServiceCoordinator.revokeGrant("grant");\n    appServiceCoordinator.renewBundle("bundle");\n    appServiceCoordinator.rejectBundle("bundle");\n  }\n  Object trustGraphExportSummary() {\n    trustGraphApiHandler.statements(Map.of());\n    try {\n      trustGraphApiHandler.statements(Map.of());\n    } catch (TrustGraphException exception) {\n      mappedTrustGraphException(exception);\n    }\n    return Map.of("metadataOnly", true, "completeWot", false);\n  }\n  Object mappedTrustGraphException(TrustGraphException exception) { return exception; }\n  void clearAppStateAfterRecoveryUninstall(String appId) { appUninstallCleanup.clearAppState(appId, true); }\n  void trustGraphReset() {\n    String unavailable = "Trust Graph stores do not expose a tested local-state reset API.";\n  }\n  Object networkBudgets() {\n    return networkBudgetService.snapshots().stream().map(AppNetworkBudgetSnapshot::toJson);\n  }\n  Object supportBundlePreview() { return Map.of(); }\n  Object supportBundleActions() {\n    redactedDetails(\n        "supportBundlePreview",\n        supportBundlePreview(recoverySupportBundle()));\n    return redactedDetails(\n        "supportBundle",\n        recoverySupportBundle());\n  }\n  Object recoverySupportBundle() { supportBundleSupplier.get(); return Map.of(); }\n  Object redactedDetails(String key, Object value) { return value; }\n  Object supportContext() { Object json = Map.of(); return redactedMap(json); }\n  Object redactedMap(Object json) { return json; }\n  String safeAuditTargetId(OperatorRecoveryTarget target) { return "sha256:"; }\n  void appendAudit(OperatorRecoveryTarget target) { safeAuditTargetId(target); }\n  String confirmationPhrase(OperatorRecoveryTarget target) { return target.safePrimaryId(); }\n}\n', encoding='utf-8')
    (recovery_dir / 'OperatorRecoveryPlan.java').write_text('record OperatorRecoveryPlan() {}\n', encoding='utf-8')
    (recovery_dir / 'OperatorRecoveryResult.java').write_text('record OperatorRecoveryResult(Object sensitiveBackup) { String marker = "sensitiveBackup"; }\n', encoding='utf-8')
    (recovery_dir / 'OperatorRecoveryTarget.java').write_text('\nrecord OperatorRecoveryTarget() {\n  Object toJson() { return safeIdentifier(value.trim()); }\n  String safePrimaryId() { return safeIdentifier(primaryId()); }\n  String safeIdentifier(String value) {\n    Object redacted = OperatorSupportRedactor.redact(value).value();\n    return redacted.equals(value) ? value : "sha256:";\n  }\n  String fingerprintSource() { return "raw-target"; }\n}\n', encoding='utf-8')
    (operator_dir / 'OperatorSupportRedactor.java').write_text('\npackage network.crypta.platform.api.operator;\n\nimport java.util.ArrayList;\nimport java.util.LinkedHashMap;\nimport java.util.LinkedHashSet;\nimport java.util.List;\nimport java.util.Map;\nimport java.util.Set;\nimport java.util.regex.Pattern;\n\nfinal class OperatorSupportRedactor {\n  private static final String REDACTED_APP_DATA_BACKUP = "<redacted-app-data-backup>";\n  private static final String REDACTED_CONTENT_URI = "<redacted-content-uri>";\n  private static final Pattern CONTENT_URI =\n      Pattern.compile("(?i)\\\\b(?:crypta:)?(?:CHK|SSK|USK|KSK)@[^\\\\s\\"\'<>]+");\n  private static final Set<String> SENSITIVE_FIELD_NAMES =\n      Set.of(\n          "formpassword",\n          "browsersession",\n          "plantoken",\n          "requestbody",\n          "rawbody",\n          "sourcepath",\n          "rollbackpath",\n          "backupbundle",\n          "payloadbase64",\n          "authorizationheader",\n          "cisecretvalue",\n          "rawappdata",\n          "privateinserturi",\n          "rawprofiledocument",\n          "rawfeedsnapshot",\n          "rawtruststatement",\n          "rawsocialmessage",\n          "appserviceinvocationbody",\n          "vaultidentitymaterial",\n          "authorization",\n          "token",\n          "privatekey",\n          "rawappdatavalue",\n          "localpath",\n          "backuppayload");\n  String[] patterns = {"private_insert_uri", "public_content_uri",\n    "raw_profile_document", "raw_feed_snapshot", "raw_trust_statement",\n    "raw_social_message", "app_service_invocation_body", "vault_identity_material",\n    "nested_archive_or_base64_backup_payload"};\n  String marker = "crypta-app-data-backup";\n\n  static Object patternsChecked() {\n    return null;\n  }\n\n  static RedactionResult redact(Object value) {\n    LinkedHashSet<String> omittedFields = new LinkedHashSet<>();\n    return new RedactionResult(redactValue(value, omittedFields), List.copyOf(omittedFields));\n  }\n\n  private static Object redactValue(Object value, LinkedHashSet<String> omittedFields) {\n    if (value instanceof Map<?, ?> map) {\n      if (isBackupPayloadMap(map)) {\n        omittedFields.add("appDataBackup");\n        return REDACTED_APP_DATA_BACKUP;\n      }\n      LinkedHashMap<String, Object> redacted = new LinkedHashMap<>();\n      for (Map.Entry<?, ?> entry : map.entrySet()) {\n        String key = String.valueOf(entry.getKey());\n        if (SENSITIVE_FIELD_NAMES.contains(normalize(key))) {\n          omittedFields.add(key);\n          continue;\n        }\n        redacted.put(key, redactValue(entry.getValue(), omittedFields));\n      }\n      return redacted;\n    }\n    if (value instanceof List<?> list) {\n      ArrayList<Object> redacted = new ArrayList<>();\n      for (Object child : list) {\n        redacted.add(redactValue(child, omittedFields));\n      }\n      return redacted;\n    }\n    if (value instanceof String text) {\n      if (text.contains("crypta-app-data-backup")) {\n        return REDACTED_APP_DATA_BACKUP;\n      }\n      return CONTENT_URI.matcher(text).replaceAll(REDACTED_CONTENT_URI);\n    }\n    return value;\n  }\n\n  private static boolean isBackupPayloadMap(Map<?, ?> map) {\n    Object kind = map.get("kind");\n    return kind instanceof String text && "crypta-app-data-backup".equals(text);\n  }\n\n  private static String normalize(String value) {\n    return value.replaceAll("[^A-Za-z0-9]", "").toLowerCase(java.util.Locale.ROOT);\n  }\n\n  record RedactionResult(Object value, List<String> omittedFields) {}\n}\n', encoding='utf-8')
    (api_dir / 'PlatformApiOperatorRoutes.java').write_text('\nfinal class PlatformApiOperatorRoutes {\n  Object route(Object segments, Object request) {\n    requireHostOperator(request);\n    if ("beta-dashboard".equals(resource)) return dashboardService.dashboard();\n    if ("support-bundle".equals(resource)) return dashboardService.supportBundle();\n    if ("support-bundle".equals(segments.get(1)) && "preview".equals(segments.get(2))) return recoveryService.supportBundlePreview();\n    if ("rc-dashboard".equals(resource)) return Map.of("dashboardKind", "operator-rc-recovery-dashboard", "operatorRcRecovery", recoveryService.dashboardState());\n    if ("network-budgets".equals(resource)) return recoveryService.networkBudgets();\n    if ("app-submissions".equals(resource)) return appSubmissionIntakeSummary();\n    if ("app-submissions".equals(segments.get(1))) return routeAppSubmissionIntakeRecord(segments.get(2), request);\n    String intake = "operator/app-submissions cryptad.appSubmissionIntakeDir CRYPTAD_APP_INTAKE_QUEUE_DIR operatorRoutesInAppContract appSubmissionIntakeSummary routeAppSubmissionIntakeRecord";\n    Object cleanup = appRoutes::clearAppStateAfterUninstall;\n    switch (segments.get(2)) { case "actions": break; case "plan": break; case "execute": break; }\n    String recoveryContext = "recoveryContext";\n    if ("backups".equals(segments.get(2))) return routeAppDataBackup(request);\n    if ("restore".equals(segments.get(2))) return routeAppDataRestore(request);\n    switch (action) { case "refresh": break; case "pause": break; case "resume": break; case "reset-backoff": break; case "reschedule-now": break; }\n    if ("plan".equals(segments.get(3))) return appDataService.planRestore(request);\n    String route = "operator/app-data";\n    String error = "host_operator_required app_data_service_unavailable";\n    return null;\n  }\n  Object routeAppDataBackup(Object request) { return null; }\n  Object routeAppDataBackupPostOnly(Object request) { return methodNotAllowed(METHOD_POST, POST_ONLY_MESSAGE); }\n  Object routeAppDataRestore(Object request) { return routeAppDataRestoreCommit(request); }\n  Object routeAppDataRestoreCommit(Object request) { return null; }\n}\n', encoding='utf-8')
    (api_dir / 'PlatformApiRouter.java').write_text(read_source(api_dir / 'PlatformApiRouter.java') + ' case "operator" -> operatorRoutes.route(segments, request);\n', encoding='utf-8')
    subscription_service_path = workspace / 'platform-api/src/main/java/network/crypta/platform/api/content/subscriptions/ContentSubscriptionService.java'
    subscription_service_path.write_text(subscription_service_path.read_text(encoding='utf-8') + 'List<Map<String, Object>> listAllForOperator() { return listAllForScheduler(); }\n' + 'void resetBackoff(String appId, String subscriptionId) {}\n' + 'void rescheduleNow(String appId, String subscriptionId) {}\n', encoding='utf-8')
    subscription_record_path = workspace / 'platform-api/src/main/java/network/crypta/platform/api/content/subscriptions/ContentSubscription.java'
    subscription_record_path.parent.mkdir(parents=True, exist_ok=True)
    subscription_record_path.write_text(subscription_record_path.read_text(encoding='utf-8') + 'ContentSubscription withBackoffReset(Object now) { return this; }\n' + 'ContentSubscription withRescheduledNow(Object now) { return this; }\n', encoding='utf-8')
    subscription_tests = workspace / 'platform-api/src/test/java/network/crypta/platform/api/content/subscriptions/ContentSubscriptionServiceTest.java'
    subscription_tests.parent.mkdir(parents=True, exist_ok=True)
    subscription_tests.write_text(subscription_tests.read_text(encoding='utf-8') + 'void resetBackoff_whenSubscriptionFailed_expectMetadataClearedWithoutFetch() {}\n' + 'void rescheduleNow_whenSubscriptionActive_expectDueTimeUpdatedWithoutFetch() {}\n', encoding='utf-8')
    (platform_api_tests / 'PlatformApiOperatorRoutesTest.java').write_text('\nclass PlatformApiOperatorRoutesTest {\n  private static final String FORM_FIELD_ASSIGNMENT = "form" + "Pass" + "word=secret-value";\n\t  void route_whenAppPrincipalRequestsOperatorDashboard_expectForbiddenBeforeDispatch() {}\n\t  void route_whenAppPrincipalRequestsOperatorRcRecovery_expectForbiddenBeforeDispatch() {}\n\t  void route_whenAppPrincipalUsesOperatorSubscriptionWrapper_expectForbidden() {}\n\t  void route_whenAppPrincipalRequestsAppDataBackupRestore_expectForbidden() {}\n\t  void route_whenOperatorUsesAppDataBackupRestore_expectSensitiveBackupAndMetadataPlan() {}\n\t  void route_whenRecoveryExecuteMissingConfirmationForDestructiveAction_expectConflict() {}\n\t  void route_whenRecoveryExecuteMissingPlanToken_expectConflict() {}\n\t  void route_whenOperatorResetsSubscriptionBackoff_expectNoFetchAndRedactedSummary() {}\n\t  void route_whenOperatorRequestsNetworkBudgets_expectSafeSnapshotsOnly() {}\n\t  void route_whenAppSubmissionIntakeQueueConfigured_expectSafeOperatorSummary() {}\n\t  void route_whenSupportBundlePreviewRequested_expectRedactionMetadataAndRecoveryContext() {}\n\t  void route_whenSupportBundleIncludesSensitiveDiagnostics_expectRedactedOutput() {\n    String path = "/work/private/catalog";\n    String secret = FORM_FIELD_ASSIGNMENT;\n    assertFalse(response.body().contains(FORM_FIELD_ASSIGNMENT));\n    assertFalse(response.body().contains("plainTextExport"));\n    assertTrue(response.body().contains("redactedLineCount"));\n  }\n  void route_whenPathParameterAttemptsRouteProxy_expectIgnored() {\n    String path = "some/arbitrary/path";\n  }\n}\n', encoding='utf-8')
    recovery_tests_dir = platform_api_tests / 'operator/recovery'
    recovery_tests_dir.mkdir(parents=True, exist_ok=True)
    (recovery_tests_dir / 'OperatorRecoveryServiceTest.java').write_text('\nclass OperatorRecoveryServiceTest {\n  void execute_whenSupportPreviewIncludesArbitraryPathParameter_expectIgnored() {}\n  void execute_whenSupportBundlePreviewRequested_expectRealPreviewArtifactBuilt() {}\n  void execute_whenSupportBundleExportRequested_expectRedactedBundleArtifactReturned() {}\n  void execute_whenPlanTokenMissing_expectConflictBeforeDispatch() {}\n  void execute_whenExportBeforeUninstallSucceeds_expectRelatedAppStateCleared() {}\n  void execute_whenExportBeforeUninstallFailsAfterBackup_expectPartialResultWithSensitiveBackup() {}\n  void execute_whenExportBeforeUninstallCleanupFails_expectPartialResultWithSensitiveBackup() {}\n  void execute_whenTrustGraphStoreUnavailable_expectFailedResultInsteadOfThrownException() {}\n  void plan_whenAppStartRequested_expectStoppedAppRequirementReported() {}\n  void plan_whenTrustGraphResetRequested_expectUnavailableInsteadOfFakeSuccess() {}\n  void planResultAndSupportContext_whenUnsafeTargetIdSupplied_expectTargetIdRedacted() {}\n  void plan_whenDestructiveUnsafeTargetIdSupplied_expectConfirmationPhraseRedacted() {}\n}\n', encoding='utf-8')
    redactor_test_dir = platform_api_tests / 'operator'
    redactor_test_dir.mkdir(parents=True, exist_ok=True)
    (redactor_test_dir / 'OperatorSupportRedactorTest.java').write_text('\nclass OperatorSupportRedactorTest {\n  void redact_whenNestedSecretsPathsAndContentUrisPresent_expectUnsafeValuesRemoved() {\n    String path = "/work/cryptad/private.txt";\n    String secret = "query-secret";\n  }\n  void redact_whenOperatorRcRecoveryContextContainsSecrets_expectUnsafeValuesRemoved() {\n    String rawTrustStatementBody = "secret";\n    String payloadBase64 = "secret";\n    String stagedBundlePath = "/work/cryptad/staging";\n  }\n  void redact_whenSecurityIncidentArtifactContainsIntakeSecrets_expectIncidentEvidenceRedacted() {}\n  void redact_whenBackupPayloadAccidentallyEntersSupportBundle_expectWholeBackupRedacted() {}\n  void redact_whenPrivacyPreservingDiagnosticsFieldsPresent_expectUnsafeFieldsOmitted() {}\n}\n', encoding='utf-8')
    (redactor_test_dir / 'OperatorBetaDashboardServiceTest.java').write_text('\nclass OperatorBetaDashboardServiceTest {\n  void supportBundle_whenSensitiveDiagnosticsPresent_expectSchemaV2SafeSummariesAndDigest() {\n    String plain = "plainTextExport";\n    String lines = "redactedLineCount";\n  }\n}\n', encoding='utf-8')
    legacy_http_dir = workspace / 'adapter-http-legacy-admin/src/main/java/network/crypta/clients/http'
    legacy_http_dir.mkdir(parents=True, exist_ok=True)
    (legacy_http_dir / 'PlatformApiToadlet.java').write_text('final class PlatformApiToadlet { boolean requiresOperatorFormPassword() { return "backups".equals(pathSegments.get(2)) || "recovery".equals(pathSegments.get(1)); } boolean requiresConsentFormPassword() { return "update-preview".equals(pathSegments.get(1)); } String route = "operator/app-data/backups"; String method = "POST"; }\n', encoding='utf-8')
    legacy_http_test_dir = workspace / 'src/test/java/network/crypta/clients/http'
    legacy_http_test_dir.mkdir(parents=True, exist_ok=True)
    (legacy_http_test_dir / 'PlatformApiToadletTest.java').write_text('class PlatformApiToadletTest { String paths = "/operator/app-data/backups /operator/app-data/restore/plan /operator/app-data/restore /operator/subscriptions/feed-reader/sub-123/refresh /operator/recovery/plan /operator/recovery/execute"; }\n', encoding='utf-8')
    operator_doc_text = 'The host/operator-only Operator beta dashboard documents operator-beta.dashboard, operator-beta.catalog-health, operator-beta.app-update-recovery, operator-beta.subscription-recovery, operator-beta.trust-review-warnings, operator-beta.app-data-quota-warnings, operator-beta.app-data-backup-restore, operator-beta.support-bundle-redaction, and operator-beta.web-shell. App-data backup restore evidence app-data.backup-restore-portability uses sensitive user data warnings. Trust Graph Local RC is local trust only, not global truth, not moderation, not blocking, not routing policy, no legacy WoT, and no crawling. Support bundles are reviewed by the operator before sharing and exclude raw request bodies and raw backup values.'
    (docs / 'operator-beta-dashboard.md').write_text(operator_doc_text, encoding='utf-8')
    (docs / 'operator-rc-recovery-and-support-workflow.md').write_text('Operator RC Recovery documents operator-rc.dashboard, operator-rc.recovery-plan-execute, operator-rc.catalog-repair, operator-rc.app-reinstall-rollback, operator-rc.export-before-uninstall, operator-rc.subscription-recovery, operator-rc.app-service-grant-recovery, operator-rc.trust-graph-recovery, operator-rc.network-budget-visibility, operator-rc.support-bundle-wizard, and operator-rc.redaction. The routes are host/operator-only, typed action-id dispatch only, plan before execute, destructive confirmation, metadata-only Trust Graph export, no global truth, no moderation, no routing policy, no raw app-data backup payloads in support bundles, no plugin runtime restoration, and no FProxy browse removal. production-security-response-runbook.md covers security incident intake. Support bundles exclude form passwords, tokens, private insert URIs, raw bodies, raw app-data values, and local paths.\n', encoding='utf-8')
    (docs / 'app-platform-beta-program.md').write_text('Operator beta dashboard operator-beta-ux-and-recovery\n', encoding='utf-8')
    (docs / 'platform-api-surface.md').write_text(read_source(docs / 'platform-api-surface.md') + '\nOperator routes are host/operator-only.\n', encoding='utf-8')
    (docs / 'privacy-preserving-beta-diagnostics.md').write_text('Privacy-preserving beta diagnostics are local-only support bundles. They exclude raw content, raw app data, private insert URIs, tokens, identity material, local paths, and legacy plaintext diagnostics from default exports.\n', encoding='utf-8')
    fixture_dir = workspace / 'tools/release-certification/fixtures'
    fixture_dir.mkdir(parents=True, exist_ok=True)
    fixture_payloads = {'support-bundle-redaction-safe.json': {'kind': 'cryptad-operator-support-bundle', 'redaction': {'status': 'pass'}, 'privacy': {'includesRawContent': False}, 'sections': {'catalog': {'status': 'available', 'sourceDigest': '0' * 64}}}, 'support-bundle-redaction-private-insert-uri.json': {'privateInsertUri': 'crypta:SSK@fake-private-insert/example'}, 'support-bundle-redaction-private-insert-uri-text.json': {'kind': 'cryptad-operator-support-bundle', 'message': 'Support text mentions crypta:SSK@fake-private-insert/example under a safe key.'}, 'support-bundle-redaction-token.json': {'authorization': 'Bearer fake-token'}, 'support-bundle-redaction-raw-profile.json': {'rawProfileDocument': {'type': 'crypta.profile.v1', 'displayName': 'Private'}}, 'support-bundle-redaction-raw-feed.json': {'rawFeedSnapshot': {'type': 'crypta.feed.snapshot.v1', 'items': []}}, 'support-bundle-redaction-raw-trust-statement.json': {'rawTrustStatement': {'type': 'crypta.trust.statement.v1'}}, 'support-bundle-redaction-raw-social-message.json': {'rawSocialMessage': {'type': 'crypta.social.message.v1', 'body': 'Private'}}, 'support-bundle-redaction-raw-app-data.json': {'rawAppDataValue': 'private-value'}, 'support-bundle-redaction-local-path.json': {'localPath': '/home/operator/.cryptad'}, 'support-bundle-redaction-private-key.json': {'privateKey': '-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----'}, 'support-bundle-redaction-app-service-body.json': {'appServiceInvocationBody': {'request': 'private'}}, 'support-bundle-redaction-nested-backup.json': {'backupPayload': {'kind': 'crypta-app-data-backup', 'apps': []}}}
    for fixture_name, fixture_payload in fixture_payloads.items():
        write_json(fixture_dir / fixture_name, fixture_payload)
    router_test = workspace / 'src/test/java/network/crypta/platform/api/PlatformApiRouterTest.java'
    router_test.parent.mkdir(parents=True, exist_ok=True)
    router_test.write_text('\nclass PlatformApiRouterTest {\n  void route_whenAppUpdateApplyRequestedWhileRunning_expectConflictJson() {\n    PlatformApiResponse response =\n        updateRouter.route(request("POST", List.of("apps", APP_ID, "updates", "apply"), Map.of()));\n    assertEquals(409, response.statusCode());\n    assertTrue(response.body().contains("\\"code\\":\\"app_running\\""));\n    verify(appHost, never()).updateFromDirectory(APP_ID, stagedDir);\n  }\n}\n', encoding='utf-8')
    catalog_handler = workspace / 'platform-api/src/main/java/network/crypta/platform/api/appcatalogs/AppCatalogsApiHandler.java'
    catalog_handler.parent.mkdir(parents=True, exist_ok=True)
    catalog_handler.write_text('\nclass AppCatalogsApiHandler {\n  static final String PARAM_SECURITY_ACKNOWLEDGED = "securityAcknowledged";\n  static final String ERROR_APP_SECURITY_DENYLISTED = "app_security_denylisted";\n  static final String ERROR_APP_SECURITY_BLOCKED = "app_security_blocked";\n  String recommendedCatalogError = "recommended_catalog_trusted_key_missing";\n  void listRecommendedCatalogs() {}\n  void addRecommended() {}\n  void sourceHealth() {}\n  void addMirror() {}\n  void rollback() {}\n  void keyRotationStatus() {}\n  java.util.Map<String, Object> securityResponseSummary() { return java.util.Map.of("securityResponse", "clear"); }\n  void refresh(String catalogId) { refresh(catalogId); }\n  void summarize() {\n    json.put("channel", channel);\n    json.put("supportStatus", supportStatus);\n    json.put("sourceDisplay", redactedCatalogSource(source));\n    json.put("lastResolvedDisplay", lastResolvedDisplay);\n    json.put("maintenance", summarizeMaintenance(entry.maintenanceMetadata()));\n    json.put("securityAdvisories", securityAdvisories);\n    json.put("defaultEntryChannel", "stable");\n    json.put("versionDifferent", versionDifferent(entry.version(), installedVersion, installed != null));\n    json.put("updateAvailable", updateAvailable(entry.version(), installedVersion, installed != null).orElse(null));\n    json.put("review", summarizeReview(entry.review()));\n    json.put("securityDecision", securityDecision(catalogId, entry.appId()));\n    json.put("installedSecurityDecision", installedSecurityDecision(entry.appId(), installedVersion));\n    json.put("compatibility", summarizeCompatibility(entry.compatibility()));\n    json.put("apiCompatibility", apiCompatibility(entry.compatibility().apiCompatibility(), entry.permissions()));\n    json.put("permissionDelta", summarizePermissionDelta(entry.permissions(), installed));\n    requireSecurityGate(securityDecision(catalogId, entry.appId()), securityAcknowledged, true);\n    securityAcknowledgementStillApplies(initialDecision, preparedDecision, securityAcknowledged);\n    AppCatalogInstallPlan plan = catalogManager.prepareInstallPlan(catalogId, normalizedAppId);\n    InstalledAppSnapshot updated = appHost.updateFromDirectory(entry.appId(), plan.stagedBundleDirectory());\n  }\n  private Object securityDecision(String catalogId, String appId) { return catalogManager.securityDecision(catalogId, appId); }\n  private Object installedSecurityDecision(String appId, String version) { return catalogManager.installedSecurityDecision(appId, version); }\n  private void requireSecurityGate(Object decision, boolean securityAcknowledged, boolean install) {}\n  private boolean securityAcknowledgementStillApplies(Object initialDecision, Object preparedDecision, boolean securityAcknowledged) { return securityAcknowledged; }\n  private static boolean versionDifferent(String catalogVersion, String installedVersion, boolean installed) { return false; }\n  private static Optional<Boolean> updateAvailable(String catalogVersion, String installedVersion, boolean installed) { return Optional.empty(); }\n  private Object summarizeMaintenance(Object metadata) { return metadata; }\n  private Object redactedCatalogSource(Object source) { return source; }\n  private String lastResolvedDisplay = "redacted";\n}\n', encoding='utf-8')
    lifecycle_doc = workspace / 'docs/app-update-lifecycle.md'
    lifecycle_doc.write_text('\nAppHost v1 uses an `apply_when_stopped` policy.\nSilent automatic update is not the default.\nApplying an update requires an operator or explicit API caller.\nThe policy modes are manual, stage, and apply_when_stopped.\nThe background scheduler uses AppUpdateService.check after live USK catalog refresh and manual remains the default.\nCatalog refresh records the last verified signed catalog state before candidate discovery.\nRelease evidence is app-update.scheduler.\nSecurity denylist gates block install, update, stage, apply, and automatic policy apply.\nWarning advisories require securityAcknowledged=true for manual actions and remain blocked for unattended automation.\nThe security acknowledgement does not bypass review, migration, channel, service dependency, digest, signed catalog, or signed bundle gates.\nRollback covers only the immutable installed bundle.\nRollback does not roll back app data directories or app cache directories.\n', encoding='utf-8')
    append_user_consent_self_test_workspace_markers(workspace)

def append_user_consent_self_test_workspace_markers(workspace: Path) -> None:
    consent_dir = workspace / "platform-api/src/main/java/network/crypta/platform/api/consent"
    consent_dir.mkdir(parents=True, exist_ok=True)
    (consent_dir / "ConsentModels.java").write_text(
        """
enum ConsentActionType { INSTALL_APP, UPDATE_APP, APP_SERVICE_GRANT, APP_DATA_MIGRATION }
enum ConsentRiskLevel { NONE, LOW, MATERIAL, BLOCKING }
enum ConsentDecisionStatus { APPROVED, REJECTED, DEFERRED, EXPIRED }
record ConsentSnapshot() { String snapshotDigest() { return ConsentSnapshotDigest.digest(this); } Object toDigestJson; }
final class ConsentSnapshotDigest { static String digest(Object snapshot) { return "sha256:preview"; } }
record ConsentRequest() {}
record ConsentDecision() {}
record ConsentAuditEvent() { String materialRiskSummary = "redacted"; }
interface ConsentAuditStore {}
final class FileConsentAuditStore implements ConsentAuditStore {}
final class ConsentPolicy {}
final class ConsentService {
  void buildInstallSnapshot() { installIdentitySection(); catalogTrustSection(); reviewSection();
    securitySection(); installPermissionsSection(); apiStabilitySection(); appDataAndBackupSection();
    serviceGrantPlaceholderSection(); }
  void buildUpdateSnapshot() { permissionDeltaSection(); updateApiStabilitySection();
    updateReviewSection(); updateCatalogSection(); updateSecuritySection(); updateMigrationSection();
    updateBackupSection(); updateServiceGrantDeltaSection(); }
  void buildServiceGrantSnapshot() { serviceGrantDependenciesSection(); }
  void requireApprovedServiceGrantIfRequired() {}
  void recordServiceGrantRejection() {}
  void updatePreviewReadOnly(String appId) {}
  void currentDigestCheck() { String stale = "stale_consent_snapshot"; current.snapshotDigest(); }
  void consumeConsentRequest(String requestId) {}
  String backup = "backup_before_update";
  String migration = "app-data migration operatorReviewRequired migrationRisk";
  String lifetime = "STORED_CONSENT_TTL MAX_STORED_REQUESTS MAX_STORED_DECISIONS";
  String redaction = "ConsentRedactor.redact materialRiskSummary FileConsentAuditStore";
}
final class ConsentApiHandler {
  // case "install-preview" case "catalog-update-preview" case "update-preview"
  // case "service-grant-preview" case "approve" case "reject" case "audit"
  void updatePreview() { consentService.updatePreview(appId, refreshCatalogs); }
  String routes = "case \\"install-preview\\" case \\"catalog-update-preview\\" case \\"update-preview\\" "
      + "case \\"service-grant-preview\\" case \\"approve\\" case \\"reject\\" case \\"audit\\"";
}
""",
        encoding="utf-8",
    )
    router = workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiRouter.java"
    router.write_text(
        read_source(router) + '\ncase "consent" -> appRoutes.routeConsentRequest(segments, request);\n',
        encoding="utf-8",
    )
    app_routes = workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiAppRoutes.java"
    app_routes.parent.mkdir(parents=True, exist_ok=True)
    app_routes.write_text(
        read_source(app_routes) + "\nString consentRequestId = \"consentRequestId\";\n",
        encoding="utf-8",
    )
    contract = workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiContract.java"
    contract.write_text(
        read_source(contract)
        + """
static final int CONSENT_CONTRACT_VERSION = 21;
static final String ROUTE_FAMILY_CONSENT = "consent";
void consentEndpoints() {
  String routes = "/consent/install-preview /consent/update-preview "
      + "/consent/catalog-update-preview /consent/service-grant-preview "
      + "/consent/approve /consent/reject /consent/defer /consent/audit";
  Object stability = PlatformApiStabilityLevel.OPERATOR_ONLY;
}
void consentEndpoint() {}
""",
        encoding="utf-8",
    )
    service_routes = (
        workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiAppServiceRoutes.java"
    )
    service_routes.write_text(
        read_source(service_routes)
        + "\nconsentService.requireApprovedServiceGrantIfRequired(bundleId, params, principal); "
        "consentService.recordServiceGrantRejection(bundleId, principal);\n",
        encoding="utf-8",
    )
    candidate = (
        workspace / "platform-api/src/main/java/network/crypta/platform/api/appupdates/AppUpdateCandidate.java"
    )
    candidate.write_text(
        read_source(candidate)
        + "\nboolean materialConsentAllowsAutomaticStage() { return permissionDeltaAllowsAutomaticStage() "
        "&& apiStabilityAllowsAutomaticStage() && securityAdvisoriesAllowAutomaticStage() "
        "&& dataMigrationAllowsAutomaticStage(); } "
        "boolean permissionDeltaAllowsAutomaticStage(){return true;} "
        "boolean apiStabilityAllowsAutomaticStage(){ Object statusValue = apiCompatibility.get(\"status\"); "
        "return statusValue instanceof String status && (\"compatible\".equals(status) || \"satisfied\".equals(status)); } "
        "boolean securityAdvisoriesAllowAutomaticStage(){ String reason = \"security_advisory\"; return securityAdvisories.isEmpty(); } "
        "boolean dataMigrationAllowsAutomaticStage(){ String reason = \"app_data_migration\"; return true; } "
        "String blocksAutoUpdate = \"blocksAutoUpdate\"; "
        "String operatorReviewRequired = \"operatorReviewRequired\";\n",
        encoding="utf-8",
    )
    update_service = (
        workspace / "platform-api/src/main/java/network/crypta/platform/api/appupdates/AppUpdateService.java"
    )
    update_service.write_text(
        read_source(update_service)
        + "\npublic synchronized Map<String, Object> preview(String appId, boolean refreshCatalogs) { return summary(appId, installed); }\n"
        "public synchronized Map<String, Object> previewForConsent(String appId, boolean refreshCatalogs) { return summary(appId, installed); }\n"
        "AppUpdateCandidate candidateWithConsentMigrationPlan(String appId, Object installed, AppUpdateCandidate candidate) { return candidate; }\n",
        encoding="utf-8",
    )
    shell = workspace / "platform-web-shell/src/main/resources/network/crypta/platform/webshell/static/web-shell.js"
    shell.write_text(
        read_source(shell)
        + """
function renderConsentPreview(preview, form) {}
function renderConsentSection(section) {}
function submitConsentDecision(preview, decision) {}
function renderCatalogOperationsNode() {}
function buildCatalogRollbackForm() {}
function catalogSourceDisplay() {}
const catalogOperations = "operations/health operations/revisions operations/key-rotation operations/emergency-refresh";
const thirdPartyIntake = "operator/app-submissions Third-party app intake renderThirdPartyIntake transparencyLogDigest redactionStatus beta_install_smoke_passed";
const consentMarkers = "consent/install-preview consent/update-preview consent/service-grant-preview "
  + "This approval is stale. Refresh the consent preview. consentRequestId snapshotDigest blocksAutoUpdate "
  + "Consent previews unavailable in read-only mode.";
""",
        encoding="utf-8",
    )
    web_shell_test = (
        workspace / "platform-web-shell/src/test/java/network/crypta/platform/webshell/WebShellResourcesTest.java"
    )
    web_shell_test.write_text(
        read_source(web_shell_test) + "\nvoid assertConsentUxMarkersPresent() {}\n",
        encoding="utf-8",
    )
    consent_test_dir = workspace / "platform-api/src/test/java/network/crypta/platform/api/consent"
    consent_test_dir.mkdir(parents=True, exist_ok=True)
    (consent_test_dir / "ConsentServiceTest.java").write_text(
        """
void installPreview_whenCatalogEntryHasMaterialMetadata_expectGroupedConsentSections() {}
void installPreview_whenSecurityDecisionBlocksInstallOnly_expectBlockingRisk() {}
void installPreview_whenReviewTrustBlocksInstallOnly_expectBlockingRisk() {}
void requireApprovedUpdate_whenDigestMatches_expectMutationAcknowledgements() {}
void requireApprovedUpdate_whenApprovalReused_expectConsentNotApproved() {}
void requireApprovedUpdate_whenApprovalExpires_expectConsentNotApprovedAndExpiredAudit() {}
void requireApprovedUpdate_whenCandidateDigestChanges_expectStaleApprovalRejected() {}
void requireApprovedUpdate_whenMigrationRequiresReview_expectMutationAcknowledgement() {}
void updatePreview_whenGetIncludesRefreshCatalogs_expectReadOnlyPreviewWithoutRefresh() {}
void updatePreview_whenPostIncludesRefreshCatalogs_expectConsentPreviewRefresh() {}
void serviceGrantPreview_whenBundleHasDependencies_expectGrantConsentSections() {}
void auditEvent_whenRiskSummaryContainsSensitiveValues_expectRedactedJson() {}
""",
        encoding="utf-8",
    )
    candidate_test = (
        workspace
        / "platform-api/src/test/java/network/crypta/platform/api/appupdates/AppUpdateCandidateTest.java"
    )
    candidate_test.write_text(
        "void toJsonValue_whenPermissionIsAdded_expectAutomaticUpdateBlockedByConsent() {}\n"
        "void toJsonValue_whenApiCompatibilityStatusUnknown_expectAutomaticUpdateBlockedByConsent() {}\n"
        "void toJsonValue_whenMigrationRequiresOperatorReview_expectAutomaticUpdateBlockedByConsent() {}\n"
        "void toJsonValue_whenSecurityAdvisoryPresent_expectAutomaticUpdateBlockedByConsent() {}\n",
        encoding="utf-8",
    )
    docs = workspace / "docs"
    docs.mkdir(parents=True, exist_ok=True)
    consent_doc_text = (
        "app-platform.user-consent-flow install consent update consent permission delta API stability "
        "review/trust service grants app-data migration backup security advisory auto-update audit "
        "stale consent non-goals"
    )
    (docs / "user-consent-and-permission-upgrade-ux.md").write_text(consent_doc_text, encoding="utf-8")
    for path in (
        "app-platform-developer-portal.md",
        "app-dev-cli.md",
        "app-catalogs.md",
        "app-service-discovery-and-grants.md",
        "app-data-store.md",
        "production-beta-release-pipeline.md",
        "release-certification.md",
    ):
        target = docs / path
        target.write_text(read_source(target) + "\n" + consent_doc_text + "\n", encoding="utf-8")
    readme = workspace / "tools/release-certification/README.md"
    readme.parent.mkdir(parents=True, exist_ok=True)
    readme.write_text(read_source(readme) + "\napp-platform.user-consent-flow\n", encoding="utf-8")

def fake_cli_python_source() -> str:
    return r'''#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

CURRENT_PLATFORM_API_CONTRACT_VERSION = 24
STABLE_BASELINE_CONTRACT_VERSION = 19


def option_value(args, name):
    for index, value in enumerate(args):
        if value == name and index + 1 < len(args):
            return args[index + 1]
    return ""


def write_text(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def property_value(path, name):
    if not path.is_file():
        return ""
    prefix = name + "="
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith(prefix):
            return stripped.split("=", 1)[1]
    return ""


def init_app(args):
    directory_text = option_value(args, "--dir")
    if not directory_text:
        return 2
    directory = Path(directory_text)
    (directory / "bin").mkdir(parents=True, exist_ok=True)
    (directory / "static/crypta-ui").mkdir(parents=True, exist_ok=True)
    write_text(
        directory / "cryptad-app.properties",
        "\n".join(
            [
                "manifest.version=1",
                "app.id=cert-smoke",
                "app.name=Certification Smoke",
                "app.version=0.1.0",
                "app.exec=bin/start.sh",
                "api.minimumVersion=1",
                f"api.maximumTestedVersion={CURRENT_PLATFORM_API_CONTRACT_VERSION}",
                "api.targetStability=stable",
                "api.experimentalCapabilitiesAccepted=false",
                "app.ui.mode=static",
                "app.ui.entry=static/index.html",
                "app.permissions=queue.read",
            ]
        )
        + "\n",
    )
    write_text(directory / "bin/start.sh", "#!/usr/bin/env sh\nexit 0\n")
    write_text(
        directory / "static/index.html",
        '<!doctype html><html lang="en"><head><meta name="viewport" content="width=device-width, initial-scale=1"><title>Certification Smoke</title><link rel="stylesheet" href="./crypta-ui/crypta-ui-tokens.css"><link rel="stylesheet" href="./crypta-ui/crypta-ui.css"><link rel="stylesheet" href="./app.css"></head><body class="cr-app"><main class="cr-shell"><section class="cr-permission-summary" data-crypta-permission-summary><code>queue.read</code></section><h1>Certification Smoke</h1></main><script src="./crypta-platform.js"></script><script src="./app.js"></script></body></html>\n',
    )
    write_text(
        directory / "static/app.js",
        'CryptaPlatform.bootstrap.load({ appId: "cert-smoke" });\n',
    )
    write_text(directory / "static/app.css", "body{}\n")
    write_text(directory / "static/crypta-ui/crypta-ui-tokens.css", ":root{--cr-space-4:1rem;}\n")
    write_text(directory / "static/crypta-ui/crypta-ui.css", ".cr-app{}.cr-shell{}.cr-button{}\n")
    write_text(directory / "static/crypta-ui/crypta-ui-components.js", 'window.CryptaUi={version:"1"};\n')
    write_text(
        directory / "static/crypta-platform.js",
        'window.CryptaPlatform={}; X="X-Crypta-App-Session";\n',
    )
    return 0


def ui_lint(args):
    output_text = option_value(args, "--json")
    bundle_text = option_value(args, "--bundle-dir")
    app_id = "cert-smoke"
    ui_mode = "static"
    if bundle_text:
        manifest = Path(bundle_text) / "cryptad-app.properties"
        app_id = property_value(manifest, "app.id") or app_id
        ui_mode = property_value(manifest, "app.ui.mode") or ui_mode
    payload = {
        "appId": app_id,
        "uiMode": ui_mode,
        "applicable": True,
        "summary": {"errors": 0, "warnings": 0, "notes": 0},
        "findings": [],
    }
    if os.environ.get("CRYPTAD_APP_SMOKE_FAKE_WRONG_UI_LINT_APP") == "1":
        payload["appId"] = "wrong-app"
    if os.environ.get("CRYPTAD_APP_SMOKE_FAKE_UI_LINT_ERRORS") == "1":
        payload["summary"]["errors"] = 1
        payload["findings"] = [{"id": "fake-error", "severity": "error"}]
    if output_text:
        if os.environ.get("CRYPTAD_APP_SMOKE_FAKE_SKIP_UI_LINT_JSON") == "1":
            return 0
        if os.environ.get("CRYPTAD_APP_SMOKE_FAKE_BAD_UI_LINT_JSON") == "1":
            write_text(Path(output_text), "{not-json\n")
            return 0
        write_text(Path(output_text), json.dumps(payload, sort_keys=True) + "\n")
    return 0


def pack_app(args):
    output_text = option_value(args, "--output")
    if os.environ.get("CRYPTAD_APP_SMOKE_FAKE_SKIP_PACK_OUTPUT") == "1":
        return 0
    if not output_text:
        return 2
    output = Path(output_text)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(b"zip")
    return 0


def create_catalog(args):
    catalog_text = option_value(args, "--catalog-file")
    if os.environ.get("CRYPTAD_APP_SMOKE_FAKE_SKIP_CATALOG_OUTPUT") == "1":
        return 0
    if not catalog_text:
        return 2
    entries = []
    review_receipts = []
    catalog_id = option_value(args, "--catalog-id") or "cert-smoke"
    catalog_name = option_value(args, "--name") or "Certification Smoke Apps"
    generated_at = option_value(args, "--generated-at") or "2026-05-01T00:00:00Z"
    index = 0
    while index < len(args):
        if args[index] == "--entry" and index + 1 < len(args):
            entries.append(Path(args[index + 1]))
            index += 2
            continue
        if args[index] == "--review-receipt" and index + 1 < len(args):
            review_receipts.append(Path(args[index + 1]))
            index += 2
            continue
        index += 1
    if not entries:
        entries = [Path("cert-smoke-entry.properties")]
    catalog = Path(catalog_text)
    app_ids = []
    lines = [
        "catalog.version=1",
        f"catalog.id={catalog_id}",
        f"catalog.name={catalog_name}",
        f"catalog.generatedAt={generated_at}",
    ]
    app_lines = []
    for descriptor in entries:
        app_id = property_value(descriptor, "app.id") or "cert-smoke"
        app_ids.append(app_id)
        artifact_path = Path(property_value(descriptor, "artifact.path") or "/tmp/cert-smoke.zip")
        artifact_size = artifact_path.stat().st_size if artifact_path.is_file() else 3
        app_lines.extend(
            [
                f"app.{app_id}.id={app_id}",
                f"app.{app_id}.name={property_value(descriptor, 'name') or 'Certification Smoke'}",
                f"app.{app_id}.version={property_value(descriptor, 'version') or '0.1.0'}",
                f"app.{app_id}.summary={property_value(descriptor, 'summary') or 'Certification smoke app.'}",
                f"app.{app_id}.bundle.uri={property_value(descriptor, 'bundle.uri') or 'file:///tmp/cert-smoke.zip'}",
                "app." + app_id + ".bundle.sha256=0000000000000000000000000000000000000000000000000000000000000000",
                f"app.{app_id}.bundle.size.bytes={artifact_size}",
                f"app.{app_id}.bundle.type=zip",
                f"app.{app_id}.permissions={property_value(descriptor, 'permissions') or 'queue.read'}",
            ]
        )
        if review_receipts:
            app_lines.extend(
                [
                    f"app.{app_id}.review.receipt.status=reviewed",
                    f"app.{app_id}.review.receipt.reviewer.key.id=cert-review",
                    f"app.{app_id}.review.receipt.policy.id=crypta-app-review-v1",
                    f"app.{app_id}.review.receipt.policy.version=1",
                ]
            )
    lines.append("catalog.entries=" + ",".join(app_ids))
    lines.extend(app_lines)
    write_text(catalog, "\n".join(lines) + "\n")
    return 0


def api_snapshot(args):
    output_text = option_value(args, "--output")
    if not output_text:
        return 2
    output = Path(output_text)
    stable_capabilities = [
        "app.data.read",
        "app.data.write",
        "content.fetch",
        "content.insert",
        "content.insert.app-document",
        "content.subscribe",
        "platform.contract.read",
        "queue.read",
        "queue.write",
    ]
    stable_endpoint_specs = [
        ("DELETE", "/app-data/namespaces/{namespace}", ["app.data.write"], 9, "Delete one app-owned durable data namespace."),
        ("DELETE", "/app-data/records/{namespace}/{key}", ["app.data.write"], 9, "Delete one bounded durable app-data record."),
        ("DELETE", "/content/subscriptions/{subscriptionId}", ["content.subscribe"], 8, "Delete one app-owned USK content subscription."),
        ("GET", "/app-data/export", ["app.data.read"], 9, "Export bounded app-owned durable data."),
        ("GET", "/app-data/namespaces", ["app.data.read"], 9, "List durable app-data namespace metadata."),
        ("GET", "/app-data/namespaces/{namespace}", ["app.data.read"], 9, "Read one durable app-data namespace metadata record."),
        ("GET", "/app-data/records", ["app.data.read"], 9, "List bounded durable app-data record summaries."),
        ("GET", "/app-data/records/{namespace}/{key}", ["app.data.read"], 9, "Read one bounded durable app-data record."),
        ("GET", "/app-data/status", ["app.data.read"], 9, "Read durable app-data status."),
        ("GET", "/content/subscriptions", ["content.subscribe"], 8, "List app-owned USK content subscriptions."),
        ("GET", "/content/subscriptions/{subscriptionId}", ["content.subscribe"], 8, "Read one app-owned USK content subscription."),
        ("GET", "/platform/contract", ["platform.contract.read"], 1, "Read the deterministic Platform API compatibility contract."),
        ("GET", "/queue", ["queue.read"], 1, "Read the queue snapshot."),
        ("GET", "/queue/count", ["queue.read"], 1, "Read queue counts."),
        ("GET", "/queue/keys", ["queue.read"], 1, "Read queue key exports."),
        ("POST", "/app-data/import", ["app.data.write"], 9, "Import bounded app-owned durable data."),
        ("POST", "/app-data/namespaces/{namespace}/schema", ["app.data.write"], 9, "Record durable app-data schema metadata."),
        ("POST", "/app-data/records", ["app.data.write"], 9, "Create or replace one bounded durable app-data record."),
        ("POST", "/content/fetch", ["content.fetch"], 6, "Fetch one bounded Crypta content document."),
        ("POST", "/content/subscriptions", ["content.fetch", "content.subscribe"], 8, "Create one app-owned bounded USK content subscription."),
        ("POST", "/content/subscriptions/{subscriptionId}/pause", ["content.subscribe"], 8, "Pause one app-owned USK content subscription."),
        ("POST", "/content/subscriptions/{subscriptionId}/refresh", ["content.fetch", "content.subscribe"], 8, "Refresh one app-owned USK content subscription."),
        ("POST", "/content/subscriptions/{subscriptionId}/resume", ["content.subscribe"], 8, "Resume one app-owned USK content subscription."),
        ("POST", "/queue/cleanup/downloads", ["queue.write"], 1, "Clean completed download requests."),
        ("POST", "/queue/cleanup/uploads", ["queue.write"], 1, "Clean completed upload requests."),
        ("POST", "/queue/downloads", ["queue.write"], 1, "Create a direct download request."),
        ("POST", "/queue/inserts/app-document", ["content.insert.app-document", "queue.write"], 5, "Create a bounded app-generated document insert request."),
        ("POST", "/queue/inserts/directory", ["content.insert", "queue.write"], 1, "Create a local directory insert request."),
        ("POST", "/queue/inserts/file", ["content.insert", "queue.write"], 1, "Create a local file insert request."),
        ("POST", "/queue/requests/priority", ["queue.write"], 1, "Change queue request priority."),
        ("POST", "/queue/requests/remove", ["queue.write"], 1, "Remove queue requests."),
        ("POST", "/queue/requests/restart", ["queue.write"], 1, "Restart queue requests."),
    ]

    def capability(name, stability, since, description):
        return {
            "name": name,
            "stability": stability,
            "sinceContractVersion": since,
            "deprecation": None,
            "description": description,
        }

    def route_family(route):
        trimmed = route.strip("/")
        return trimmed.split("/", 1)[0] if trimmed else "platform"

    def endpoint(
        method,
        route,
        capabilities,
        since,
        description,
        stability="stable",
        host_operator=True,
        app_process=True,
        app_browser=True,
    ):
        action = route.strip("/").replace("/", ".").replace("{", "").replace("}", "")
        return {
            "routeFamily": route_family(route),
            "method": method,
            "routeTemplate": route,
            "actionLabel": action or route,
            "requiredCapabilities": capabilities,
            "hostOperatorBypassAllowed": host_operator,
            "appProcessPrincipalsAllowed": app_process,
            "appBrowserPrincipalsAllowed": app_browser,
            "stability": stability,
            "sinceContractVersion": since,
            "deprecation": None,
            "description": description,
        }

    stable_endpoints = [
        endpoint(method, route, capabilities, since, description)
        for method, route, capabilities, since, description in stable_endpoint_specs
    ]
    experimental_endpoints = [
        endpoint("GET", "/trust-graph/audit", ["trust.read"], 10, "List recent redacted Trust Graph Local RC audit events.", "experimental"),
        endpoint("POST", "/trust-graph/import-uri", ["content.fetch", "trust.write"], 10, "Fetch and import one bounded trust statement from a Crypta content URI.", "experimental"),
        endpoint("GET", "/trust-graph/statements/{fingerprint}", ["trust.read"], 15, "Read one redacted local Trust Graph RC statement summary.", "experimental"),
        endpoint("POST", "/trust-graph/statements/{fingerprint}/deprecate", ["trust.write"], 15, "Mark one imported statement deprecated in local lifecycle policy.", "experimental"),
        endpoint("POST", "/trust-graph/statements/{fingerprint}/revoke", ["trust.write"], 15, "Mark one imported statement revoked in local lifecycle policy.", "experimental"),
        endpoint("POST", "/trust-graph/statements/{fingerprint}/reactivate", ["trust.write"], 15, "Reactivate one imported statement in local lifecycle policy.", "experimental"),
        endpoint("POST", "/app-vault/identities/{identityId}/social-message", ["vault.identities.read", "vault.identities.use"], 11, "Create a signed bounded social message.", "experimental"),
        endpoint("GET", "/app-services", ["app.services.read"], 12, "List advertised local app services.", "experimental"),
        endpoint("GET", "/app-services/audit", [], 12, "List recent redacted app-service audit events.", "operator-only", True, False, False),
        endpoint("GET", "/app-services/dependencies", ["app.services.read"], 16, "List caller-visible app-service dependency graph.", "experimental"),
        endpoint("GET", "/app-services/dependencies/consumers/{consumerAppId}", ["app.services.read"], 16, "Read dependency graph metadata for one consumer app.", "experimental"),
        endpoint("GET", "/app-services/grant-bundles", ["app.services.read"], 16, "List grant-bundle proposals visible to the caller.", "experimental"),
        endpoint("POST", "/app-services/grant-bundles", ["app.services.call"], 16, "Request an operator-reviewed grant bundle.", "experimental"),
        endpoint("POST", "/app-services/grant-bundles/{bundleId}/approve", [], 16, "Approve one pending app-service grant bundle.", "operator-only", True, False, False),
        endpoint("POST", "/app-services/grant-bundles/{bundleId}/reject", [], 16, "Reject one pending app-service grant bundle.", "operator-only", True, False, False),
        endpoint("POST", "/app-services/grant-bundles/{bundleId}/renew", [], 16, "Renew one approved app-service grant bundle.", "operator-only", True, False, False),
        endpoint("GET", "/app-services/grants", ["app.services.read"], 12, "List app-service grants visible to the caller.", "experimental"),
        endpoint("POST", "/app-services/grants", ["app.services.call"], 12, "Request an operator-approved local app-service grant.", "experimental"),
        endpoint("POST", "/app-services/grants/{grantId}/approve", [], 12, "Approve one pending app-service grant.", "operator-only", True, False, False),
        endpoint("POST", "/app-services/grants/{grantId}/revoke", ["app.services.call"], 12, "Revoke one app-service grant.", "experimental"),
        endpoint("GET", "/app-services/{providerAppId}/services", ["app.services.read"], 12, "List services advertised by one provider app.", "experimental"),
        endpoint("GET", "/app-services/{providerAppId}/services/{serviceId}", ["app.services.read"], 12, "Read one advertised local app-service descriptor.", "experimental"),
        endpoint("POST", "/app-services/{providerAppId}/services/{serviceId}/invoke", ["app.services.call"], 12, "Invoke one bounded local app service.", "experimental"),
        endpoint("GET", "/app-catalogs/{catalogId}/mirrors", ["catalogs.read"], 23, "List catalog primary and mirror endpoints.", "experimental", True, False, False),
        endpoint("POST", "/app-catalogs/{catalogId}/mirrors", ["catalogs.manage"], 23, "Add one catalog mirror endpoint.", "experimental", True, False, False),
        endpoint("POST", "/app-catalogs/{catalogId}/mirrors/{mirrorId}", ["catalogs.manage"], 23, "Update one catalog mirror endpoint.", "experimental", True, False, False),
        endpoint("DELETE", "/app-catalogs/{catalogId}/mirrors/{mirrorId}", ["catalogs.manage"], 23, "Remove one catalog mirror endpoint.", "experimental", True, False, False),
        endpoint("GET", "/app-catalogs/{catalogId}/operations/health", ["catalogs.read"], 23, "Read catalog source and mirror health.", "experimental", True, False, False),
        endpoint("GET", "/app-catalogs/{catalogId}/operations/revisions", ["catalogs.read"], 23, "List verified catalog rollback candidates.", "experimental", True, False, False),
        endpoint("GET", "/app-catalogs/{catalogId}/operations/key-rotation", ["catalogs.read"], 23, "Read catalog signing-key rotation status.", "experimental", True, False, False),
        endpoint("POST", "/app-catalogs/{catalogId}/operations/refresh-primary", ["catalogs.manage"], 23, "Refresh only the primary catalog endpoint.", "experimental", True, False, False),
        endpoint("POST", "/app-catalogs/{catalogId}/operations/rollback", ["catalogs.manage"], 23, "Roll back to a verified catalog revision.", "experimental", True, False, False),
        endpoint("POST", "/app-catalogs/{catalogId}/operations/emergency-refresh", ["catalogs.manage"], 23, "Refresh catalogs for emergency advisory propagation.", "experimental", True, False, False),
    ]
    contract = {
        "apiVersion": "v1",
        "contractVersion": CURRENT_PLATFORM_API_CONTRACT_VERSION,
        "generatedBy": "cryptad",
        "stabilityPolicy": "self-test",
        "stableBaseline": {
            "name": "1.0",
            "contractVersion": STABLE_BASELINE_CONTRACT_VERSION,
            "capabilityCount": len(stable_capabilities),
            "endpointCount": len(stable_endpoint_specs),
            "capabilities": stable_capabilities,
            "endpoints": [f"{method} {route}" for method, route, _capabilities, _since, _description in stable_endpoint_specs],
        },
        "compatibilityWindow": {
            "schemaVersion": 1,
            "baselineName": "1.0",
            "baselineContractVersion": STABLE_BASELINE_CONTRACT_VERSION,
            "currentContractVersion": CURRENT_PLATFORM_API_CONTRACT_VERSION,
            "supportPhase": "beta",
            "supportWindowStartedRelease": "production-beta",
            "minimumDeprecationWindowContractVersions": 2,
            "minimumScheduledRemovalWindowContractVersions": 2,
            "stableRemovalRequiresNewBaseline": True,
            "stableRemovalRequiresPreviousSnapshot": True,
            "stableRemovalRequiresExplicitWaiver": True,
            "criticalStableRemovalWaiverAllowed": False,
            "experimentalGraduationRequiresReview": True,
            "experimentalGraduationRequiresStableReferenceUpdate": True,
            "previousSnapshotRequiredInProductionBeta": True,
            "policyDocument": "docs/platform-api-compatibility-support-window.md",
        },
        "capabilities": [
            capability("queue.read", "stable", 1, "Read queue state."),
            capability("queue.write", "stable", 1, "Create and mutate queue requests."),
            capability("platform.contract.read", "stable", 1, "Read contract snapshots."),
            capability("app.data.read", "stable", 9, "Read app-owned durable state."),
            capability("app.data.write", "stable", 9, "Write app-owned durable state."),
            capability("content.fetch", "stable", 6, "Fetch bounded content."),
            capability("content.insert", "stable", 1, "Create content insert requests."),
            capability("content.insert.app-document", "stable", 5, "Create app-generated document insert requests."),
            capability("content.subscribe", "stable", 8, "Manage bounded content subscriptions."),
            capability("trust.read", "experimental", 7, "Read local Trust Graph RC state and lifecycle."),
            capability("trust.write", "experimental", 7, "Mutate local Trust Graph RC anchors and lifecycle."),
            capability("vault.identities.read", "experimental", 11, "Read app-visible identity metadata."),
            capability("vault.identities.use", "experimental", 11, "Use bounded AppVault signing routes."),
            capability("app.services.read", "experimental", 12, "Discover local app services and grants."),
            capability("app.services.call", "experimental", 12, "Request grants and invoke approved services."),
            capability("catalogs.read", "experimental", 23, "Read signed app-catalog sources and entries."),
            capability("catalogs.manage", "experimental", 23, "Manage signed app-catalog sources and operations."),
        ],
        "endpoints": stable_endpoints + experimental_endpoints,
    }
    write_text(output, json.dumps({"contract": contract}, sort_keys=True) + "\n")
    return 0


def main():
    if len(sys.argv) < 2:
        return 0
    command = sys.argv[1]
    args = sys.argv[2:]
    if command == "init":
        return init_app(args)
    if command == "validate":
        return 0
    if command == "ui":
        subcommand = args[0] if args else ""
        if subcommand == "lint":
            return ui_lint(args[1:])
        return 0
    if command == "pack":
        return pack_app(args)
    if command == "catalog":
        subcommand = args[0] if args else ""
        if subcommand == "create":
            return create_catalog(args[1:])
        if subcommand in {"sign", "verify"}:
            return 0
    if command == "api":
        subcommand = args[0] if args else ""
        if subcommand == "snapshot":
            return api_snapshot(args[1:])
    if command == "compat":
        return 0
    if command in {"sign", "verify"}:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''

def make_fake_cli(workspace: Path) -> Path:
    bin_dir = workspace / "platform-devtools/build/install/crypta-app/bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    cli = bin_dir / ("crypta-app.bat" if platform.system() == "Windows" else "crypta-app")
    helper = bin_dir / "crypta-app-fake.py"
    helper.write_text(fake_cli_python_source(), encoding="utf-8")
    if platform.system() == "Windows":
        cli.write_text(
            """@echo off
py -3 "%~dp0crypta-app-fake.py" %*
if not errorlevel 9009 exit /b %ERRORLEVEL%
python3 "%~dp0crypta-app-fake.py" %*
exit /b %ERRORLEVEL%
""",
            encoding="utf-8",
        )
    else:
        cli.write_text(
            """#!/usr/bin/env sh
set -eu
script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
cmd="${1:-}"
if [ "$#" -gt 0 ]; then shift; fi
case "$cmd" in
  init)
    dir=""
    while [ "$#" -gt 0 ]; do
      if [ "$1" = "--dir" ]; then dir="$2"; shift 2; else shift; fi
    done
    mkdir -p "$dir/bin" "$dir/static/crypta-ui"
    printf '%s\n' 'manifest.version=1' 'app.id=cert-smoke' 'app.name=Certification Smoke' 'app.version=0.1.0' 'app.exec=bin/start.sh' 'api.minimumVersion=1' 'api.maximumTestedVersion=24' 'api.targetStability=stable' 'api.experimentalCapabilitiesAccepted=false' 'app.ui.mode=static' 'app.ui.entry=static/index.html' 'app.permissions=queue.read' > "$dir/cryptad-app.properties"
    printf '%s\n' '#!/usr/bin/env sh' 'exit 0' > "$dir/bin/start.sh"
    printf '%s\n' '<!doctype html><html lang="en"><head><meta name="viewport" content="width=device-width, initial-scale=1"><title>Certification Smoke</title><link rel="stylesheet" href="./crypta-ui/crypta-ui-tokens.css"><link rel="stylesheet" href="./crypta-ui/crypta-ui.css"><link rel="stylesheet" href="./app.css"></head><body class="cr-app"><main class="cr-shell"><section class="cr-permission-summary" data-crypta-permission-summary><code>queue.read</code></section><h1>Certification Smoke</h1></main><script src="./crypta-platform.js"></script><script src="./app.js"></script></body></html>' > "$dir/static/index.html"
    printf '%s\n' 'CryptaPlatform.bootstrap.load({ appId: "cert-smoke" });' > "$dir/static/app.js"
    printf '%s\n' 'body{}' > "$dir/static/app.css"
    printf '%s\n' ':root{--cr-space-4:1rem;}' > "$dir/static/crypta-ui/crypta-ui-tokens.css"
    printf '%s\n' '.cr-app{}.cr-shell{}.cr-button{}' > "$dir/static/crypta-ui/crypta-ui.css"
    printf '%s\n' 'window.CryptaUi={version:"1"};' > "$dir/static/crypta-ui/crypta-ui-components.js"
    printf '%s\n' 'window.CryptaPlatform={}; X="X-Crypta-App-Session";' > "$dir/static/crypta-platform.js"
    ;;
  validate)
    exit 0
    ;;
  ui)
    sub="${1:-}"; shift || true
    if [ "$sub" = "lint" ]; then
      out=""
      bundle=""
      while [ "$#" -gt 0 ]; do
        case "$1" in
          --json)
            out="$2"
            shift 2
            ;;
          --bundle-dir)
            bundle="$2"
            shift 2
            ;;
          *)
            shift
            ;;
        esac
      done
      if [ -n "$out" ]; then
        if [ "${CRYPTAD_APP_SMOKE_FAKE_SKIP_UI_LINT_JSON:-0}" = "1" ]; then
          exit 0
        fi
        mkdir -p "$(dirname "$out")"
        if [ "${CRYPTAD_APP_SMOKE_FAKE_BAD_UI_LINT_JSON:-0}" = "1" ]; then
          printf '%s\n' '{not-json' > "$out"
          exit 0
        fi
        app_id="cert-smoke"
        ui_mode="static"
        if [ -n "$bundle" ] && [ -f "$bundle/cryptad-app.properties" ]; then
          app_id="$(awk -F= '$1 == "app.id" {print substr($0, index($0, "=") + 1); exit}' "$bundle/cryptad-app.properties")"
          ui_mode="$(awk -F= '$1 == "app.ui.mode" {print substr($0, index($0, "=") + 1); exit}' "$bundle/cryptad-app.properties")"
          app_id="${app_id:-cert-smoke}"
          ui_mode="${ui_mode:-static}"
        fi
        if [ "${CRYPTAD_APP_SMOKE_FAKE_WRONG_UI_LINT_APP:-0}" = "1" ]; then
          app_id="wrong-app"
        fi
        error_count="0"
        findings="[]"
        if [ "${CRYPTAD_APP_SMOKE_FAKE_UI_LINT_ERRORS:-0}" = "1" ]; then
          error_count="1"
          findings='[{"id":"fake-error","severity":"error"}]'
        fi
        printf '{"appId":"%s","applicable":true,"findings":%s,"summary":{"errors":%s,"notes":0,"warnings":0},"uiMode":"%s"}\n' "$app_id" "$findings" "$error_count" "$ui_mode" > "$out"
      fi
      exit 0
    fi
    ;;
  pack)
    out=""
    while [ "$#" -gt 0 ]; do
      if [ "$1" = "--output" ]; then out="$2"; shift 2; else shift; fi
    done
    if [ "${CRYPTAD_APP_SMOKE_FAKE_SKIP_PACK_OUTPUT:-0}" = "1" ]; then
      exit 0
    fi
    printf 'zip' > "$out"
    ;;
  catalog)
    sub="$1"; shift
    case "$sub" in
      create)
        if [ "${CRYPTAD_APP_SMOKE_FAKE_SKIP_CATALOG_OUTPUT:-0}" = "1" ]; then
          exit 0
        fi
        python3 - "$@" <<'PY'
import sys
from pathlib import Path

args = sys.argv[1:]

def option(name, default=""):
    for index, value in enumerate(args):
        if value == name and index + 1 < len(args):
            return args[index + 1]
    return default

def values(name):
    found = []
    index = 0
    while index < len(args):
        if args[index] == name and index + 1 < len(args):
            found.append(Path(args[index + 1]))
            index += 2
        else:
            index += 1
    return found

def prop(path, name):
    if not path.is_file():
        return ""
    prefix = name + "="
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith(prefix):
            return stripped.split("=", 1)[1]
    return ""

catalog_text = option("--catalog-file")
if not catalog_text:
    raise SystemExit(2)
catalog = Path(catalog_text)
entries = values("--entry") or [Path("cert-smoke-entry.properties")]
review_receipts = values("--review-receipt")
app_ids = []
lines = [
    "catalog.version=1",
    "catalog.id=" + option("--catalog-id", "cert-smoke"),
    "catalog.name=" + option("--name", "Certification Smoke Apps"),
    "catalog.generatedAt=" + option("--generated-at", "2026-05-01T00:00:00Z"),
]
app_lines = []
for descriptor in entries:
    app_id = prop(descriptor, "app.id") or "cert-smoke"
    app_ids.append(app_id)
    artifact = Path(prop(descriptor, "artifact.path") or "/tmp/cert-smoke.zip")
    size = artifact.stat().st_size if artifact.is_file() else 3
    app_lines.extend([
        f"app.{app_id}.id={app_id}",
        f"app.{app_id}.name={prop(descriptor, 'name') or 'Certification Smoke'}",
        f"app.{app_id}.version={prop(descriptor, 'version') or '0.1.0'}",
        f"app.{app_id}.summary={prop(descriptor, 'summary') or 'Certification smoke app.'}",
        f"app.{app_id}.bundle.uri={prop(descriptor, 'bundle.uri') or 'file:///tmp/cert-smoke.zip'}",
        f"app.{app_id}.bundle.sha256=0000000000000000000000000000000000000000000000000000000000000000",
        f"app.{app_id}.bundle.size.bytes={size}",
        f"app.{app_id}.bundle.type=zip",
        f"app.{app_id}.permissions={prop(descriptor, 'permissions') or 'queue.read'}",
    ])
    if review_receipts:
        app_lines.extend([
            f"app.{app_id}.review.receipt.status=reviewed",
            f"app.{app_id}.review.receipt.reviewer.key.id=cert-review",
            f"app.{app_id}.review.receipt.policy.id=crypta-app-review-v1",
            f"app.{app_id}.review.receipt.policy.version=1",
        ])
catalog.parent.mkdir(parents=True, exist_ok=True)
catalog.write_text("\\n".join(lines + ["catalog.entries=" + ",".join(app_ids)] + app_lines) + "\\n", encoding="utf-8")
PY
        ;;
      sign|verify)
        exit 0
        ;;
    esac
    ;;
  api)
    sub="${1:-}"
    if [ "$#" -gt 0 ]; then shift; fi
    case "$sub" in
      snapshot)
        if command -v python3 >/dev/null 2>&1; then
          python3 "$script_dir/crypta-app-fake.py" api snapshot "$@"
          exit $?
        fi
        output=""
        while [ "$#" -gt 0 ]; do
          if [ "$1" = "--output" ]; then output="$2"; shift 2; else shift; fi
        done
        if [ -z "$output" ]; then
          exit 2
        fi
        mkdir -p "$(dirname "$output")"
        cat > "$output" <<'JSON'
{
  "contract": {
    "apiVersion": "v1",
    "contractVersion": 24,
    "generatedBy": "cryptad",
    "stabilityPolicy": "self-test",
    "stableBaseline": {
      "name": "1.0",
      "contractVersion": 19,
      "capabilityCount": 9,
      "endpointCount": 32,
      "capabilities": [
        "app.data.read",
        "app.data.write",
        "content.fetch",
        "content.insert",
        "content.insert.app-document",
        "content.subscribe",
        "platform.contract.read",
        "queue.read",
        "queue.write"
      ],
      "endpoints": [
        "DELETE /app-data/namespaces/{namespace}",
        "DELETE /app-data/records/{namespace}/{key}",
        "DELETE /content/subscriptions/{subscriptionId}",
        "GET /app-data/export",
        "GET /app-data/namespaces",
        "GET /app-data/namespaces/{namespace}",
        "GET /app-data/records",
        "GET /app-data/records/{namespace}/{key}",
        "GET /app-data/status",
        "GET /content/subscriptions",
        "GET /content/subscriptions/{subscriptionId}",
        "GET /platform/contract",
        "GET /queue",
        "GET /queue/count",
        "GET /queue/keys",
        "POST /app-data/import",
        "POST /app-data/namespaces/{namespace}/schema",
        "POST /app-data/records",
        "POST /content/fetch",
        "POST /content/subscriptions",
        "POST /content/subscriptions/{subscriptionId}/pause",
        "POST /content/subscriptions/{subscriptionId}/refresh",
        "POST /content/subscriptions/{subscriptionId}/resume",
        "POST /queue/cleanup/downloads",
        "POST /queue/cleanup/uploads",
        "POST /queue/downloads",
        "POST /queue/inserts/app-document",
        "POST /queue/inserts/directory",
        "POST /queue/inserts/file",
        "POST /queue/requests/priority",
        "POST /queue/requests/remove",
        "POST /queue/requests/restart"
      ]
    },
    "capabilities": [
      {
        "name": "queue.read",
        "stability": "stable",
        "sinceContractVersion": 1,
        "deprecation": null,
        "description": "Read queue state."
      },
      {
        "name": "queue.write",
        "stability": "stable",
        "sinceContractVersion": 1,
        "deprecation": null,
        "description": "Create and mutate queue requests."
      },
      {
        "name": "platform.contract.read",
        "stability": "stable",
        "sinceContractVersion": 1,
        "deprecation": null,
        "description": "Read contract snapshots."
      },
      {
        "name": "app.data.read",
        "stability": "stable",
        "sinceContractVersion": 9,
        "deprecation": null,
        "description": "Read app-owned durable state."
      },
      {
        "name": "app.data.write",
        "stability": "stable",
        "sinceContractVersion": 9,
        "deprecation": null,
        "description": "Write app-owned durable state."
      },
      {
        "name": "content.fetch",
        "stability": "stable",
        "sinceContractVersion": 6,
        "deprecation": null,
        "description": "Fetch bounded content."
      },
      {
        "name": "content.insert",
        "stability": "stable",
        "sinceContractVersion": 1,
        "deprecation": null,
        "description": "Create content insert requests."
      },
      {
        "name": "content.insert.app-document",
        "stability": "stable",
        "sinceContractVersion": 5,
        "deprecation": null,
        "description": "Create app-generated document insert requests."
      },
      {
        "name": "content.subscribe",
        "stability": "stable",
        "sinceContractVersion": 8,
        "deprecation": null,
        "description": "Manage bounded content subscriptions."
      },
      {
        "name": "trust.read",
        "stability": "experimental",
        "sinceContractVersion": 7,
        "deprecation": null,
        "description": "Read local Trust Graph RC state and lifecycle."
      },
      {
        "name": "trust.write",
        "stability": "experimental",
        "sinceContractVersion": 7,
        "deprecation": null,
        "description": "Mutate local Trust Graph RC anchors and lifecycle."
      },
      {
        "name": "vault.identities.read",
        "stability": "experimental",
        "sinceContractVersion": 11,
        "deprecation": null,
        "description": "Read app-visible identity metadata."
      },
      {
        "name": "vault.identities.use",
        "stability": "experimental",
        "sinceContractVersion": 11,
        "deprecation": null,
        "description": "Use bounded AppVault signing routes."
      },
      {
        "name": "app.services.read",
        "stability": "experimental",
        "sinceContractVersion": 12,
        "deprecation": null,
        "description": "Discover local app services and grants."
      },
      {
        "name": "app.services.call",
        "stability": "experimental",
        "sinceContractVersion": 12,
        "deprecation": null,
        "description": "Request grants and invoke approved services."
      }
    ],
    "endpoints": [
      {
        "routeFamily": "queue",
        "method": "GET",
        "routeTemplate": "/queue",
        "actionLabel": "queue.read",
        "requiredCapabilities": [
          "queue.read"
        ],
        "hostOperatorBypassAllowed": true,
        "appProcessPrincipalsAllowed": true,
        "appBrowserPrincipalsAllowed": true,
        "stability": "stable",
        "sinceContractVersion": 1,
        "deprecation": null,
        "description": "Read queue state."
      },
      {
        "method": "GET",
        "routeTemplate": "/app-data/status",
        "stability": "stable"
      },
      {
        "method": "GET",
        "routeTemplate": "/app-data/namespaces",
        "stability": "stable"
      },
      {
        "method": "GET",
        "routeTemplate": "/app-data/namespaces/{namespace}",
        "stability": "stable"
      },
      {
        "method": "POST",
        "routeTemplate": "/app-data/namespaces/{namespace}/schema",
        "stability": "stable"
      },
      {
        "method": "DELETE",
        "routeTemplate": "/app-data/namespaces/{namespace}",
        "stability": "stable"
      },
      {
        "method": "GET",
        "routeTemplate": "/app-data/records",
        "stability": "stable"
      },
      {
        "method": "GET",
        "routeTemplate": "/app-data/records/{namespace}/{key}",
        "stability": "stable"
      },
      {
        "method": "POST",
        "routeTemplate": "/app-data/records",
        "stability": "stable"
      },
      {
        "method": "DELETE",
        "routeTemplate": "/app-data/records/{namespace}/{key}",
        "stability": "stable"
      },
      {
        "method": "GET",
        "routeTemplate": "/app-data/export",
        "stability": "stable"
      },
      {
        "method": "POST",
        "routeTemplate": "/app-data/import",
        "stability": "stable"
      },
      {
        "method": "GET",
        "routeTemplate": "/trust-graph/audit",
        "stability": "stable"
      },
      {
        "method": "POST",
        "routeTemplate": "/trust-graph/import-uri",
        "stability": "stable"
      },
      {
        "method": "GET",
        "routeTemplate": "/trust-graph/statements/{fingerprint}",
        "requiredCapabilities": [
          "trust.read"
        ],
        "stability": "experimental",
        "sinceContractVersion": 15
      },
      {
        "method": "POST",
        "routeTemplate": "/trust-graph/statements/{fingerprint}/deprecate",
        "requiredCapabilities": [
          "trust.write"
        ],
        "stability": "experimental",
        "sinceContractVersion": 15
      },
      {
        "method": "POST",
        "routeTemplate": "/trust-graph/statements/{fingerprint}/revoke",
        "requiredCapabilities": [
          "trust.write"
        ],
        "stability": "experimental",
        "sinceContractVersion": 15
      },
      {
        "method": "POST",
        "routeTemplate": "/trust-graph/statements/{fingerprint}/reactivate",
        "requiredCapabilities": [
          "trust.write"
        ],
        "stability": "experimental",
        "sinceContractVersion": 15
      },
      {
        "method": "POST",
        "routeTemplate": "/app-vault/identities/{identityId}/social-message",
        "requiredCapabilities": [
          "vault.identities.read",
          "vault.identities.use"
        ],
        "stability": "experimental"
      },
      {
        "method": "GET",
        "routeTemplate": "/app-services",
        "stability": "experimental"
      },
      {
        "method": "GET",
        "routeTemplate": "/app-services/audit",
        "stability": "experimental"
      },
      {
        "method": "GET",
        "routeTemplate": "/app-services/dependencies",
        "stability": "experimental"
      },
      {
        "method": "GET",
        "routeTemplate": "/app-services/dependencies/consumers/{consumerAppId}",
        "stability": "experimental"
      },
      {
        "method": "GET",
        "routeTemplate": "/app-services/grant-bundles",
        "stability": "experimental"
      },
      {
        "method": "POST",
        "routeTemplate": "/app-services/grant-bundles",
        "stability": "experimental"
      },
      {
        "method": "POST",
        "routeTemplate": "/app-services/grant-bundles/{bundleId}/approve",
        "stability": "experimental"
      },
      {
        "method": "POST",
        "routeTemplate": "/app-services/grant-bundles/{bundleId}/reject",
        "stability": "experimental"
      },
      {
        "method": "POST",
        "routeTemplate": "/app-services/grant-bundles/{bundleId}/renew",
        "stability": "experimental"
      },
      {
        "method": "GET",
        "routeTemplate": "/app-services/grants",
        "stability": "experimental"
      },
      {
        "method": "POST",
        "routeTemplate": "/app-services/grants",
        "stability": "experimental"
      },
      {
        "method": "POST",
        "routeTemplate": "/app-services/grants/{grantId}/approve",
        "stability": "experimental"
      },
      {
        "method": "POST",
        "routeTemplate": "/app-services/grants/{grantId}/revoke",
        "stability": "experimental"
      },
      {
        "method": "GET",
        "routeTemplate": "/app-services/{providerAppId}/services",
        "stability": "experimental"
      },
      {
        "method": "GET",
        "routeTemplate": "/app-services/{providerAppId}/services/{serviceId}",
        "stability": "experimental"
      },
      {
        "method": "POST",
        "routeTemplate": "/app-services/{providerAppId}/services/{serviceId}/invoke",
        "stability": "experimental"
      }
    ]
  }
}
JSON
        ;;
      *)
        exit 2
        ;;
    esac
    ;;
  compat)
    sub="${1:-}"
    if [ "$#" -gt 0 ]; then shift; fi
    case "$sub" in
      verify)
        contract=""
        target=""
        while [ "$#" -gt 0 ]; do
          case "$1" in
            --contract)
              contract="$2"
              shift 2
              ;;
            --bundle-dir|--catalog-entry)
              target="$2"
              shift 2
              ;;
            --strict)
              shift
              ;;
            *)
              shift
              ;;
          esac
        done
        if [ -z "$contract" ] || [ ! -f "$contract" ]; then
          exit 2
        fi
        if [ -z "$target" ]; then
          exit 2
        fi
        ;;
      *)
        exit 2
        ;;
    esac
    ;;
  sign|verify)
    exit 0
    ;;
esac
""",
            encoding="utf-8",
        )
        cli.chmod(0o755)
    return cli

def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.self_test:
        run_self_test(Path(__file__).resolve().parents[2])
        print("app-platform-smoke self-test passed")
        return 0
    settings = settings_from_args(args)
    summary, exit_code = run(settings)
    print(f"App platform smoke {summary['status']}: {settings.out_dir / SUMMARY_FILE_NAME}")
    return exit_code
