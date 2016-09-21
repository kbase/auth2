package us.kbase.auth2.lib.identity;

import java.util.UUID;

public class RemoteIdentity {
	
	//TODO JAVADOC
	//TODO TEST
	
	private final RemoteIdentityID remoteID;
	private final RemoteIdentityDetails details;
	
	public RemoteIdentity(
			final RemoteIdentityID remoteID,
			final RemoteIdentityDetails details) {
		super();
		//TODO INPUT check for null & .trim().isEmpty()
		if (remoteID == null) {
			throw new NullPointerException("id");
		}
		if (details == null) {
			throw new NullPointerException("details");
		}
		this.remoteID = remoteID;
		this.details = details;
	}
	
	public RemoteIdentityWithID withID() {
		return withID(UUID.randomUUID());
	}
	
	public RemoteIdentityWithID withID(final UUID id) {
		return new RemoteIdentityWithID(id, this.remoteID, this.details);
	}

	public RemoteIdentityID getRemoteID() {
		return remoteID;
	}
	
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
