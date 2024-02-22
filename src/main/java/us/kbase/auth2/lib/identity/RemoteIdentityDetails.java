package us.kbase.auth2.lib.identity;

/** A set of potentially mutable details about a remote identity. The identity provider may
 * change these details at any time.
 * @author gaprice@lbl.gov
 *
 */
public class RemoteIdentityDetails {

	private final String username;
	private final String fullname;
	private final String email;
	
	/** Create a new set of details.
	 * @param username the user name of the identity.
	 * @param fullname the full name of the identity. Null is acceptable.
	 * @param email the email address of the identity. Null is acceptable.
	 */
	public RemoteIdentityDetails(
			final String username,
			final String fullname,
			final String email) {
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

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((email == null) ? 0 : email.hashCode());
		result = prime * result + ((fullname == null) ? 0 : fullname.hashCode());
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
		builder.append("]");
		return builder.toString();
	}
}
