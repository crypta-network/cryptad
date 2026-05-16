/**
 * Queue control-plane endpoints for Platform API v1.
 *
 * <p>This package owns the transport-neutral queue surface that sits between the legacy HTTP bridge
 * and the detached queue runtime ports. It exists to make queue operations first-class Platform API
 * features instead of requiring the Web Shell to call the legacy queue toadlet directly for routine
 * operator actions.
 *
 * <p>The current read model remains intentionally transitional. Queue reads still originate from
 * detached HTML snapshots produced by the existing runtime page port, then leave this package as
 * stable JSON envelopes after request-local placeholders are stripped. Mutations and direct
 * download creation already cross the SPI more directly, which keeps later queue phases free to
 * replace the transitional read model without reworking the basic control-plane routing contract.
 *
 * <p>Generated app-document inserts are deliberately narrower than local file inserts. They accept
 * bounded app-supplied document bytes, hand them to the queue browser-upload path for trusted
 * persistent bucket storage, and keep local source paths and private insert URI material out of
 * public responses.
 */
package network.crypta.platform.api.queue;
