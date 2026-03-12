package network.crypta.client.async;

import network.crypta.keys.USK;

/**
 * Shared dependencies for configuring a {@link USKPollingRound}.
 *
 * <p>This bundles the stable collaborators used during polling rounds so they can be reused when
 * scheduling background polling.
 *
 * @param attempts polling attempt manager used to track active attempts
 * @param storeChecks coordinator for datastore checks
 * @param dbrHintFetches date-hint fetch coordinator
 * @param subscribers registry for USK callbacks
 * @param uskManager USK manager used to look up latest slots
 * @param origUSK base USK that is being polled
 * @param realTimeFlag whether polling is scheduled with real-time bias
 */
record USKPollingRoundContext(
    USKAttemptManager attempts,
    USKStoreCheckCoordinator storeChecks,
    USKDateHintFetches dbrHintFetches,
    USKSubscriberRegistry subscribers,
    USKManager uskManager,
    USK origUSK,
    boolean realTimeFlag) {}
