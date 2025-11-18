package us.kbase.auth2.lib.token;

import java.util.HashMap;
import java.util.Map;

/** An enumeration representing the multi-factor authentication status of a user's login. */
public enum MFAStatus {

	/* first arg is ID, second arg is description. ID CANNOT change
	 * since that field is stored in the DB. Description is exposed in the service API / UI.
	 * This allows for changing the variable name or API name without breaking the database
	 * records.
	 */

	/** User authenticated with MFA during token creation. */
	USED			("Used", "Used"),

	/** User explicitly chose not to use MFA when available. */
	NOT_USED		("NotUsed", "NotUsed"),

	/** MFA status catch all. Covers
	 * - source did not provide enough information to determine MFA status
	 * - source does not support MFA
	 * - MFA is not applicable to the data (e.g. token types other than Login)
	 */
	UNKNOWN			("Unknown", "Unknown");

	private static final Map<String, MFAStatus> STATUS_MAP = new HashMap<>();
	static {
		for (final MFAStatus status: MFAStatus.values()) {
			STATUS_MAP.put(status.getID(), status);
		}
	}

	private final String id;
	private final String description;

	private MFAStatus(final String id, final String description) {
		this.id = id;
		this.description = description;
	}

	/** Get the ID of this MFA status.
	 * @return the ID.
	 */
	public String getID() {
		return id;
	}

	/** Get the description of this MFA status.
	 * @return the description.
	 */
	public String getDescription() {
		return description;
	}

	/** Get an MFA status from its ID.
	 * @param id the ID of the MFA status.
	 * @return the MFA status.
	 * @throws IllegalArgumentException if there is no MFA status matching the ID.
	 */
	public static MFAStatus fromID(final String id) {
		if (!STATUS_MAP.containsKey(id)) {
			throw new IllegalArgumentException("Invalid MFA status: " + id);
		}
		return STATUS_MAP.get(id);
	}
}
