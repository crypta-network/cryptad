package network.crypta.client.filter;

/**
 * Flags describing content risks associated with a MIME type.
 *
 * <p>Each flag indicates whether a particular content aspect is considered dangerous even after
 * filtering, allowing higher-level callers to enforce additional policy.
 *
 * @param dangerousLinks whether embedded links are considered risky
 * @param dangerousInlines whether inline external references are considered risky
 * @param dangerousScripting whether scripts or active content are considered risky
 * @param dangerousReadMetadata whether metadata is risky to read
 * @param dangerousWriteMetadata whether metadata is risky to write
 * @param dangerousToWriteEvenWithFilter whether writing remains unsafe even after filtering
 */
public record FilterMIMETypeDangerousFlags(
    boolean dangerousLinks,
    boolean dangerousInlines,
    boolean dangerousScripting,
    boolean dangerousReadMetadata,
    boolean dangerousWriteMetadata,
    boolean dangerousToWriteEvenWithFilter) {}
