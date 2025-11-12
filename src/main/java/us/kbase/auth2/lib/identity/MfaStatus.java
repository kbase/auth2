package us.kbase.auth2.lib.identity;

import java.util.HashMap;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonValue;

/** An enumeration representing the multi-factor authentication status of a user's login.
 * @author dlyon@lbl.gov
 *
 */
public enum MfaStatus {

	/* first arg is ID, second arg is description. ID CANNOT change
	 * since that field is stored in the DB.
	 */
	/** User authenticated with MFA during token creation. */
	USED			("Used", "MFA used"),
	/** User explicitly chose not to use MFA when available. */
	NOT_USED		("NotUsed", "MFA not used"),
	/** MFA status unknown or not applicable to authentication method. */
	UNKNOWN			("Unknown", "MFA status unknown");

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
	@JsonValue
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
	public static MfaStatus fromID(final String id) {
		if (!STATUS_MAP.containsKey(id)) {
			throw new IllegalArgumentException("Invalid MFA status: " + id);
		}
		return STATUS_MAP.get(id);
	}
}
