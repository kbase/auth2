package us.kbase.auth2.lib.identity;

import static us.kbase.auth2.lib.Utils.nonNull;

import java.util.UUID;

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
		nonNull(remoteID, "remoteID");
		nonNull(details, "details");
		this.remoteID = remoteID;
		this.details = details;
	}
	
	/** Add a new, random local ID to this remote identity. 
	 * @return this remote identity with a new local ID.
	 */
	public RemoteIdentityWithLocalID withID() {
		return withID(UUID.randomUUID());
	}
	
	/** Associate a pre-existing local ID to this remote identity.
	 * @param id the ID to associate with this identity.
	 * @return this remote idenity with the provided local ID.
	 */
	public RemoteIdentityWithLocalID withID(final UUID id) {
		return new RemoteIdentityWithLocalID(id, this.remoteID, this.details);
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
		result = prime * result + details.hashCode();
		result = prime * result + remoteID.hashCode();
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
		if (!details.equals(other.details)) {
			return false;
		}
		if (!remoteID.equals(other.remoteID)) {
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
