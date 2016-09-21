package us.kbase.auth2.lib.identity;

import java.util.UUID;

public class RemoteIdentityWithID extends RemoteIdentity {
	
	//TODO JAVADOC
	//TODO TEST
	
	private final UUID id;
	
	public RemoteIdentityWithID(
			final UUID id,
			final RemoteIdentityID remoteID,
			final RemoteIdentityDetails details) {
		super(remoteID, details);
		if (id == null) {
			throw new NullPointerException("id");
		}
		this.id = id;
	}
	
	public UUID getID() {
		return id;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + ((id == null) ? 0 : id.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!super.equals(obj)) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		RemoteIdentityWithID other = (RemoteIdentityWithID) obj;
		if (id == null) {
			if (other.id != null) {
				return false;
			}
		} else if (!id.equals(other.id)) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("RemoteIdentityWithID [id=");
		builder.append(id);
		builder.append(", getRemoteID()=");
		builder.append(getRemoteID());
		builder.append(", getDetails()=");
		builder.append(getDetails());
		builder.append("]");
		return builder.toString();
	}

	
}