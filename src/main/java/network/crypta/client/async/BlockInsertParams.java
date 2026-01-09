package network.crypta.client.async;

import network.crypta.client.InsertContext;

/**
 * Bundles the shared constructor arguments for block-level inserters.
 *
 * <p>This record groups the parent putter, callback, and immediate notification context required to
 * set up a block insert. It intentionally performs no validation or normalization; callers and the
 * receiving inserter remain responsible for enforcing any invariants.
 *
 * @param parent parent putter coordinating progress and persistence
 * @param ctx insert context controlling retries, compression, and scheduling hints
 * @param callback completion callback invoked for encode/success/failure transitions
 * @param token numeric correlation token used by callers for logging or indexing
 * @param tokenObject opaque token returned to callers; may be {@code null}
 * @param addToParent whether to increment parent must-succeed counters on construction
 * @param context runtime context used for immediate parent notifications during construction
 */
public record BlockInsertParams(
    BaseClientPutter parent,
    InsertContext ctx,
    PutCompletionCallback callback,
    int token,
    Object tokenObject,
    boolean addToParent,
    ClientContext context) {}
