package us.kbase.auth2.lib.identity;

import static java.util.Objects.requireNonNull;

/** An identity provided by a 3rd party identity provider such as Google, Globus, etc.
 * @author gaprice@lbl.gov
 *
 */
public class RemoteIdentity {
	
	private final RemoteIdentityID remoteID;
	private final RemoteIdentityDetails details;
	
	/** Create a remote identity.
	 * @param remoteID the immutable ID of this identity. The identity provider should not change
	 * any part of this ID.
	 * @param details other details about the identity. These details may be changed by the
	 * identity provider.
	 */
	public RemoteIdentity(
			final RemoteIdentityID remoteID,
			final RemoteIdentityDetails details) {
		requireNonNull(remoteID, "remoteID");
		requireNonNull(details, "details");
		this.remoteID = remoteID;
		this.details = details;
	}
	
	/** Get the immutable ID for this identity.
	 * @return the ID.
	 */
	public RemoteIdentityID getRemoteID() {
		return remoteID;
	}
	
	/** Get the details for this identity.
	 * @return the identity details.
	 */
	public RemoteIdentityDetails getDetails() {
		return details;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((details == null) ? 0 : details.hashCode());
		result = prime * result + ((remoteID == null) ? 0 : remoteID.hashCode());
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
		RemoteIdentity other = (RemoteIdentity) obj;
		if (details == null) {
			if (other.details != null) {
				return false;
			}
		} else if (!details.equals(other.details)) {
			return false;
		}
		if (remoteID == null) {
			if (other.remoteID != null) {
				return false;
			}
		} else if (!remoteID.equals(other.remoteID)) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("RemoteIdentity [remoteID=");
		builder.append(remoteID);
		builder.append(", details=");
		builder.append(details);
		builder.append("]");
		return builder.toString();
	}

}
