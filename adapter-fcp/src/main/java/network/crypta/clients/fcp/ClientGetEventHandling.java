package network.crypta.clients.fcp;

import java.util.Objects;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.client.events.ClientEvent;
import network.crypta.client.events.ClientEventDispatchContext;
import network.crypta.client.events.ClientEventListener;
import network.crypta.client.events.EnterFiniteCooldownEvent;
import network.crypta.client.events.ExpectedFileSizeEvent;
import network.crypta.client.events.ExpectedHashesEvent;
import network.crypta.client.events.ExpectedMIMEEvent;
import network.crypta.client.events.SendingToNetworkEvent;
import network.crypta.client.events.SplitfileCompatibilityMode;
import network.crypta.client.events.SplitfileCompatibilityModeEvent;
import network.crypta.client.events.SplitfileProgressEvent;
import network.crypta.support.io.NativeThread;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Translates {@link ClientEvent} updates emitted by {@link network.crypta.client.FetchContext} into
 * FCP-level progress messages, while keeping the coupling-heavy event taxonomy out of {@link
 * ClientGet}.
 *
 * <p>The helper exists primarily to satisfy Sonar rule {@code java:S6539} ("Monster Class") by
 * separating the event-to-message translation responsibility from the core request lifecycle and
 * persistence logic owned by {@link ClientGet}.
 */
final class ClientGetEventHandling implements ClientEventListener {
  private static final Logger LOG = LoggerFactory.getLogger(ClientGetEventHandling.class);

  private final ClientGet request;

  private record EventProgress(FCPMessage message, int verbosityMask) {}

  ClientGetEventHandling(ClientGet request) {
    this.request = Objects.requireNonNull(request, "request");
  }

  @Override
  public void receive(ClientEvent event, ClientEventDispatchContext context) {
    if (LOG.isDebugEnabled()) LOG.debug("Receiving {} on {}", event, request);
    if (event instanceof SplitfileCompatibilityModeEvent compatibilityModeEvent) {
      handleCompatibilityMode(compatibilityModeEvent, context);
      return;
    }
    EventProgress eventProgress = createEventProgress(event);
    if (eventProgress == null) {
      return;
    }
    if ((request.verbosity & eventProgress.verbosityMask()) == 0) {
      return;
    }
    request.queueProgressMessageInner(eventProgress.message(), eventProgress.verbosityMask());
  }

  private EventProgress createEventProgress(ClientEvent event) {
    if (event instanceof SplitfileProgressEvent progressEvent) {
      return handleSplitfileProgress(progressEvent);
    }
    if (event instanceof SendingToNetworkEvent) {
      synchronized (request.persistenceLock()) {
        request.state().markSentToNetwork();
      }
      return new EventProgress(
          new SendingToNetworkMessage(request.identifier, request.global),
          ClientGet.VERBOSITY_SENT_TO_NETWORK);
    }
    if (event instanceof ExpectedHashesEvent hashesEvent) {
      return handleExpectedHashes(hashesEvent);
    }
    if (event instanceof ExpectedMIMEEvent mimeEvent) {
      return handleExpectedMime(mimeEvent);
    }
    if (event instanceof ExpectedFileSizeEvent sizeEvent) {
      return handleExpectedSize(sizeEvent);
    }
    if (event instanceof EnterFiniteCooldownEvent cooldownEvent) {
      return new EventProgress(
          new EnterFiniteCooldown(request.identifier, request.global, cooldownEvent.wakeupTime),
          ClientGet.VERBOSITY_ENTER_FINITE_COOLDOWN);
    }
    LOG.error("Unknown event {}", event);
    return null;
  }

  private EventProgress handleSplitfileProgress(SplitfileProgressEvent event) {
    SimpleProgressMessage message =
        new SimpleProgressMessage(request.identifier, request.global, event);
    synchronized (request.persistenceLock()) {
      request.state().setProgressPending(message);
    }
    if (request.client != null) {
      RequestStatusCache cache = request.client.getRequestStatusCache();
      if (cache != null) {
        cache.updateStatus(request.identifier, event);
      }
    }
    return new EventProgress(message, ClientGet.VERBOSITY_SPLITFILE_PROGRESS);
  }

  private EventProgress handleExpectedHashes(ExpectedHashesEvent event) {
    ExpectedHashes hashes = new ExpectedHashes(event, request.identifier, request.global);
    boolean accepted;
    synchronized (request.persistenceLock()) {
      accepted = request.state().trySetExpectedHashes(hashes);
    }
    if (!accepted) {
      return null;
    }
    return new EventProgress(hashes, ClientGet.VERBOSITY_EXPECTED_HASHES);
  }

  private EventProgress handleExpectedMime(ExpectedMIMEEvent event) {
    synchronized (request.persistenceLock()) {
      request.state().setFoundDataMimeType(event.expectedMIMEType);
    }
    if (request.client != null) {
      RequestStatusCache cache = request.client.getRequestStatusCache();
      if (cache != null) {
        cache.updateExpectedMIME(request.identifier, event.expectedMIMEType);
      }
    }
    return new EventProgress(
        new ExpectedMIME(request.identifier, request.global, event.expectedMIMEType),
        ClientGet.VERBOSITY_EXPECTED_TYPE);
  }

  private EventProgress handleExpectedSize(ExpectedFileSizeEvent event) {
    synchronized (request.persistenceLock()) {
      request.state().setFoundDataLength(event.expectedSize);
    }
    if (request.client != null) {
      RequestStatusCache cache = request.client.getRequestStatusCache();
      if (cache != null) {
        cache.updateExpectedDataLength(request.identifier, event.expectedSize);
      }
    }
    return new EventProgress(
        new ExpectedDataLength(request.identifier, request.global, event.expectedSize),
        ClientGet.VERBOSITY_EXPECTED_SIZE);
  }

  private void handleCompatibilityMode(
      SplitfileCompatibilityModeEvent event, ClientEventDispatchContext context) {
    if (request.persistence == ClientRequest.Persistence.FOREVER
        && context.hasLoadedPersistentState()) {
      try {
        context.queuePersistentEventTask(
            () -> {
              synchronized (request.persistenceLock()) {
                request
                    .state()
                    .mergeCompatibilityMode(
                        toFcpCompatibilityMode(event.minCompatibilityMode),
                        toFcpCompatibilityMode(event.maxCompatibilityMode),
                        event.splitfileCryptoKey,
                        event.dontCompress,
                        event.bottomLayer);
              }
              return false;
            },
            NativeThread.PriorityLevel.HIGH_PRIORITY.value);
      } catch (PersistenceDisabledException _) {
        // Not much we can do.
      }
    } else {
      synchronized (request.persistenceLock()) {
        request
            .state()
            .mergeCompatibilityMode(
                toFcpCompatibilityMode(event.minCompatibilityMode),
                toFcpCompatibilityMode(event.maxCompatibilityMode),
                event.splitfileCryptoKey,
                event.dontCompress,
                event.bottomLayer);
      }
    }
  }

  private static FcpCompatibilityMode toFcpCompatibilityMode(SplitfileCompatibilityMode mode) {
    return FcpCompatibilityMode.byCode(mode.code);
  }
}
