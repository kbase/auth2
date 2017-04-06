package us.kbase.auth2.lib;

import static us.kbase.auth2.lib.Utils.nonNull;
import static us.kbase.auth2.lib.Utils.noNulls;

import java.time.Instant;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import us.kbase.auth2.lib.identity.RemoteIdentity;

/** A set of temporary identities.
 * @author gaprice@lbl.gov
 *
 */
public class TemporaryIdentities {
	
	private final UUID id;
	private final Instant created;
	private final Instant expires;
	private final Set<RemoteIdentity> identities;
	
	/** Create a new set of temporary identities.
	 * @param id the ID of the identity set.
	 * @param created when the identity set was created.
	 * @param expires when the identity set expires from the system.
	 * @param identities the identities.
	 */
	public TemporaryIdentities(
			final UUID id,
			final Instant created,
			final Instant expires,
			final Set<RemoteIdentity> identities) {
		nonNull(id, "id");
		nonNull(identities, "identities");
		nonNull(created, "created");
		nonNull(expires, "expires");
		noNulls(identities, "null item in identities");
		this.id = id;
		this.identities = Collections.unmodifiableSet(new HashSet<>(identities));
		this.created = created;
		this.expires = expires;
	}

	/** Get the ID of the identity set.
	 * @return the ID.
	 */
	public UUID getId() {
		return id;
	}

	/** Get the identities.
	 * @return the identities.
	 */
	public Set<RemoteIdentity> getIdentities() {
		return identities;
	}

	/** Get the date of creation for the identity set.
	 * @return the creation date.
	 */
	public Instant getCreated() {
		return created;
	}

	/** Get the date the identity set expires from the system.
	 * @return the expiration date.
	 */
	public Instant getExpires() {
		return expires;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((created == null) ? 0 : created.hashCode());
		result = prime * result + ((expires == null) ? 0 : expires.hashCode());
		result = prime * result + ((id == null) ? 0 : id.hashCode());
		result = prime * result + ((identities == null) ? 0 : identities.hashCode());
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
		TemporaryIdentities other = (TemporaryIdentities) obj;
		if (created == null) {
			if (other.created != null) {
				return false;
			}
		} else if (!created.equals(other.created)) {
			return false;
		}
		if (expires == null) {
			if (other.expires != null) {
				return false;
			}
		} else if (!expires.equals(other.expires)) {
			return false;
		}
		if (id == null) {
			if (other.id != null) {
				return false;
			}
		} else if (!id.equals(other.id)) {
			return false;
		}
		if (identities == null) {
			if (other.identities != null) {
				return false;
			}
		} else if (!identities.equals(other.identities)) {
			return false;
		}
		return true;
	}
}
