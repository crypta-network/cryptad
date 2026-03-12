/**
 * Client events layer that reports progress, state changes, and informational notifications emitted
 * by client operations.
 *
 * <p>This package defines a small, decoupled event model used by higher layers to observe what is
 * happening inside client requests without binding to internal control flow. Producers emit
 * lightweight event objects that carry a human-readable description and a stable integer code,
 * while listeners subscribe to those events to log, render UI feedback, or trigger follow-up work.
 * Typical call paths originate in request starters or schedulers, which raise events as milestones
 * are reached; UI or service components consume the stream to communicate status to users or other
 * systems.
 *
 * <p>Events are designed to be read-only and safe to share across threads. Producers should
 * dispatch quickly and avoid invoking listener code that blocks for long periods. When persistence
 * or heavy I/O is required in response to an event, listeners should defer work to background
 * executors provided by the surrounding client context rather than performing it inline. Textual
 * descriptions are intended for operators and end users, whereas integer codes enable programmatic
 * filtering and correlation.
 *
 * <ul>
 *   <li>Responsibilities: surface client progress and state transitions to observers.
 *   <li>Key types: event producers, event listeners, and immutable event values.
 *   <li>Dispatch: synchronous or asynchronous depending on producer; keep handlers fast.
 *   <li>Typical categories: progress updates, expected metadata, warnings, and completion.
 * </ul>
 */
package network.crypta.client.events;
