package us.kbase.auth2.lib.identity;

/** A set of potentially mutable details about a remote identity. The identity provider may
 * change these details at any time.
 *
 * Important Note on MFA Status: The MFA (multi-factor authentication) status field in this
 * class is session-only and is never persisted to identity documents in the database. The MFA
 * status is extracted during OAuth callbacks from the identity provider and flows through to
 * token creation, where it is stored on the token itself. When identities are loaded from the
 * database, the MFA status will always be {@link MfaStatus#UNKNOWN} since it is not stored.
 * This is by design - MFA status is transient information relevant only to the current
 * authentication session.
 *
 * @author gaprice@lbl.gov
 *
 */
public class RemoteIdentityDetails {

	private final String username;
	private final String fullname;
	private final String email;
	private final MfaStatus mfa;
	
	/** Create a new set of details.
	 * @param username the user name of the identity.
	 * @param fullname the full name of the identity. Null is acceptable.
	 * @param email the email address of the identity. Null is acceptable.
	 */
	public RemoteIdentityDetails(
			final String username,
			final String fullname,
			final String email) {
		this(username, fullname, email, MfaStatus.Unknown);
	}
	
	/** Create a new set of details.
	 * @param username the user name of the identity.
	 * @param fullname the full name of the identity. Null is acceptable.
	 * @param email the email address of the identity. Null is acceptable.
	 * @param mfa the multi-factor authentication status.
	 */
	public RemoteIdentityDetails(
			final String username,
			final String fullname,
			final String email,
			final MfaStatus mfa) {
		super();
		if (username == null || username.trim().isEmpty()) {
			throw new IllegalArgumentException(
					"username cannot be null or empty");
		}
		this.username = username.trim();
		if (fullname == null || fullname.trim().isEmpty()) {
			this.fullname = null;
		} else {
			this.fullname = fullname.trim();
		}
		if (email == null || email.trim().isEmpty()) {
			this.email = null;
		} else {
			this.email = email.trim();
		}
		this.mfa = requireNonNull(mfa, "mfa");
	}

	/** Get the user name for the identity.
	 * @return the user name.
	 */
	public String getUsername() {
		return username;
	}

	/** Get the full name for the identity, or null if none was provided.
	 * @return the full name.
	 */
	public String getFullname() {
		return fullname;
	}
	/** Get the email address for the identity, or null if none was provided.
	 * @return the email address.
	 */
	public String getEmail() {
		return email;
	}
	
	/** Get the multi-factor authentication status.
	 * @return the MFA status.
	 */
	public MfaStatus getMfa() {
		return mfa;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((email == null) ? 0 : email.hashCode());
		result = prime * result + ((fullname == null) ? 0 : fullname.hashCode());
		result = prime * result + ((mfa == null) ? 0 : mfa.hashCode());
		result = prime * result + ((username == null) ? 0 : username.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		RemoteIdentityDetails other = (RemoteIdentityDetails) obj;
		if (email == null) {
			if (other.email != null) {
				return false;
			}
		} else if (!email.equals(other.email)) {
			return false;
		}
		if (fullname == null) {
			if (other.fullname != null) {
				return false;
			}
		} else if (!fullname.equals(other.fullname)) {
			return false;
		}
		if (mfa == null) {
			if (other.mfa != null) {
				return false;
			}
		} else if (!mfa.equals(other.mfa)) {
			return false;
		}
		if (username == null) {
			if (other.username != null) {
				return false;
			}
		} else if (!username.equals(other.username)) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("RemoteIdentityDetails [username=");
		builder.append(username);
		builder.append(", fullname=");
		builder.append(fullname);
		builder.append(", email=");
		builder.append(email);
		builder.append(", mfa=");
		builder.append(mfa == null ? null : mfa.getID());
		builder.append("]");
		return builder.toString();
	}
}
