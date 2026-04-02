/**
 * Client layer utilities and types for handling high-level operations such as metadata parsing,
 * MIME type handling, and unpacking of container formats.
 *
 * <p>This package groups the components used by higher-level client flows to describe and interpret
 * stored content. Typical call patterns include parsing metadata to learn how a resource is laid
 * out, selecting an appropriate strategy (single block, split-file, or container traversal), and
 * coordinating follow-up actions in collaboration with node and transport layers. While these types
 * provide the structure and decisions necessary to fetch or insert complex resources, the actual
 * network I/O and scheduling are handled elsewhere in the system.
 *
 * <p>Many classes here favor immutability for clarity when passing parsed descriptions across
 * threads. Where mutation is necessary, implementations document their thread-safety guarantees and
 * expected usage. Errors are surfaced using precise, purpose-specific exceptions that distinguish
 * malformed inputs from inputs that are well-formed but incomplete, enabling callers to react with
 * either immediate failure or a resolve-and-retry workflow as appropriate.
 *
 * <p>Common responsibilities include:
 *
 * <ul>
 *   <li>Parsing and validating content metadata and associated descriptors.
 *   <li>Mapping metadata to retrieval or insertion plans for complex resources.
 *   <li>Identifying and unpacking supported container formats when requested.
 *   <li>Describing prerequisites that must be resolved before an operation can proceed.
 * </ul>
 *
 * @see java.net.URI
 * @see java.nio.file.Path
 */
package network.crypta.client;
