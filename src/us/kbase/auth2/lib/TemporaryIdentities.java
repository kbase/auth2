package us.kbase.auth2.lib;

import static us.kbase.auth2.lib.Utils.checkStringNoCheckedException;
import static us.kbase.auth2.lib.Utils.nonNull;
import static us.kbase.auth2.lib.Utils.noNulls;

import java.time.Instant;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import com.google.common.base.Optional;

import us.kbase.auth2.lib.exceptions.ErrorType;
import us.kbase.auth2.lib.identity.RemoteIdentity;

/** A set of temporary identities, or an error that was stored instead of the identities.
 * @author gaprice@lbl.gov
 *
 */
public class TemporaryIdentities {
	
	private final UUID id;
	private final Instant created;
	private final Instant expires;
	private final Optional<Set<RemoteIdentity>> identities;
	private final Optional<String> error;
	private final Optional<ErrorType> errorType;
	
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
		this.identities = Optional.of(Collections.unmodifiableSet(new HashSet<>(identities)));
		this.created = created;
		this.expires = expires;
		this.error = Optional.absent();
		this.errorType = Optional.absent();
	}
	
	/** Create a error report describing why the identities could not be created.
	 * @param id the ID of the identity set.
	 * @param created when the identity set was created.
	 * @param expires when the identity set expires from the system.
	 * @param error the error.
	 * @param errorType the type of the error.
	 */
	public TemporaryIdentities(
			final UUID id,
			final Instant created,
			final Instant expires,
			final String error,
			final ErrorType errorType) {
		nonNull(id, "id");
		nonNull(created, "created");
		nonNull(expires, "expires");
		checkStringNoCheckedException(error, "error");
		nonNull(errorType, "errorType");
		this.id = id;
		this.identities = Optional.absent();
		this.created = created;
		this.expires = expires;
		this.error = Optional.of(error);
		this.errorType = Optional.of(errorType);
	}

	/** Get the ID of the identity set.
	 * @return the ID.
	 */
	public UUID getId() {
		return id;
	}

	/** Get the identities, if any.
	 * @return the identities.
	 */
	public Optional<Set<RemoteIdentity>> getIdentities() {
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
	
	/** Returns the error, if any.
	 * @return the error.
	 */
	public Optional<String> getError() {
		return error;
	}
	
	/** Get the type of the error, if any.
	 * @return the error type.
	 */
	public Optional<ErrorType> getErrorType() {
		return errorType;
	}
	
	/** Returns true if an error is present.
	 * @return true if an error is present.
	 */
	public boolean hasError() {
		return error.isPresent();
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((created == null) ? 0 : created.hashCode());
		result = prime * result + ((error == null) ? 0 : error.hashCode());
		result = prime * result + ((errorType == null) ? 0 : errorType.hashCode());
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
		if (error == null) {
			if (other.error != null) {
				return false;
			}
		} else if (!error.equals(other.error)) {
			return false;
		}
		if (errorType == null) {
			if (other.errorType != null) {
				return false;
			}
		} else if (!errorType.equals(other.errorType)) {
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
