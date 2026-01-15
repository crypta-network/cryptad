package network.crypta.node.simulator;

import java.util.List;

/**
 * Groups per-run state used during long-term fetch replay.
 *
 * <p>This record combines the mutable CSV output buffer with the {@link FetchRequestContext}
 * required to fetch historical single-block URIs. It is designed for the long-term simulator
 * harness, where a single execution reads existing status rows and appends new results while
 * reusing shared fetch collaborators. Callers typically create one instance in the main flow after
 * configuring the fetch context, then pass it through the status-processing helpers that append CSV
 * tokens and issue fetches.
 *
 * <p>The record itself is immutable, but it references mutable structures: the {@code csvLine} list
 * accumulates output tokens and is expected to be appended in order, and the {@code
 * FetchRequestContext} holds a {@code FetchContext} that may be modified during setup. The harness
 * currently treats both as single-threaded resources; if multiple threads append or modify the
 * context, external synchronization is required.
 *
 * <ul>
 *   <li><b>Responsibility:</b> Carry the per-run CSV buffer and fetch collaborators together.
 *   <li><b>Lifecycle:</b> Construct once per simulator run and pass through parsing helpers.
 *   <li><b>Threading:</b> Safe to share only with coordinated mutation of referenced state.
 * </ul>
 *
 * @param csvLine ordered CSV tokens collected for the current run; appended to as work proceeds
 * @param fetchRequestContext shared client, context, and request client used for fetch attempts
 * @see FetchRequestContext
 */
public record FetchRunContext(List<String> csvLine, FetchRequestContext fetchRequestContext) {}
