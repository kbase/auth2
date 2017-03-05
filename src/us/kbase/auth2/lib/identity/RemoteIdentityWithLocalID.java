package us.kbase.auth2.lib.identity;

import static us.kbase.auth2.lib.Utils.nonNull;

import java.util.UUID;

/** An identity provided by a 3rd party identity provider such as Google, Globus, etc., with an
 * associated local ID.
 * @author gaprice@lbl.gov
 *
 */
public class RemoteIdentityWithLocalID extends RemoteIdentity {
	
	private final UUID id;
	
	/** Create a remote identity with a local ID.
	 * @param id the local ID.
	 * @param remoteID the remote identity ID.
	 * @param details the identity details.
	 */
	public RemoteIdentityWithLocalID(
			final UUID id,
			final RemoteIdentityID remoteID,
			final RemoteIdentityDetails details) {
		super(remoteID, details);
		nonNull(id, "id");
		this.id = id;
	}
	
	/** Get the local ID.
	 * @return the local ID.
	 */
	public UUID getID() {
		return id;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + id.hashCode();
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!super.equals(obj)) { // this'll handle different class
			return false;
		}
		RemoteIdentityWithLocalID other = (RemoteIdentityWithLocalID) obj;
		if (!id.equals(other.id)) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("RemoteIdentityWithLocalID [id=");
		builder.append(id);
		builder.append(", getRemoteID()=");
		builder.append(getRemoteID());
		builder.append(", getDetails()=");
		builder.append(getDetails());
		builder.append("]");
		return builder.toString();
	}

	
}