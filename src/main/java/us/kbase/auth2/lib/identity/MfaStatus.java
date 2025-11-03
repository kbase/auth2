package us.kbase.auth2.lib.identity;

import java.util.HashMap;
import java.util.Map;

/** An enumeration representing the multi-factor authentication status of a user's login.
 * @author dlyon@lbl.gov
 *
 */
public enum MfaStatus {

	/* first arg is ID, second arg is description. ID CANNOT change
	 * since that field is stored in the DB.
	 */
	/** User authenticated with MFA during token creation. */
	Used			("USED", "MFA used"),
	/** User explicitly chose not to use MFA when available. */
	NotUsed			("NOT_USED", "MFA not used"),
	/** MFA status unknown or not applicable to authentication method. */
	Unknown			("UNKNOWN", "MFA status unknown");

	private static final Map<String, MfaStatus> STATUS_MAP = new HashMap<>();
	static {
		for (final MfaStatus status: MfaStatus.values()) {
			STATUS_MAP.put(status.getID(), status);
		}
	}

	private final String id;
	private final String description;

	private MfaStatus(final String id, final String description) {
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
	 * @return the MFA status, or Unknown if the ID is null, empty, or not recognized.
	 */
	public static MfaStatus fromID(final String id) {
		if (id == null || id.trim().isEmpty()) {
			return Unknown;
		}
		final MfaStatus status = STATUS_MAP.get(id);
		if (status == null) {
			return Unknown;
		}
		return status;
	}
}
