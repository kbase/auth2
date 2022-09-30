package us.kbase.auth2.lib;

import static us.kbase.auth2.lib.Utils.checkStringNoCheckedException;
import static us.kbase.auth2.lib.Utils.nonNull;
import static us.kbase.auth2.lib.Utils.noNulls;

import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import com.google.common.base.Optional;

import us.kbase.auth2.lib.exceptions.ErrorType;
import us.kbase.auth2.lib.identity.RemoteIdentity;

/** Temporary session data that may include a set of temporary identities and / or an associated
 * user, or an error that was stored instead of the identities.
 * @author gaprice@lbl.gov
 *
 */
public class TemporarySessionData { 
	
	private final Operation op;
	private final UUID id;
	private final Instant created;
	private final Instant expires;
	private final Optional<Set<RemoteIdentity>> identities;
	private final Optional<String> error;
	private final Optional<ErrorType> errorType;
	private final Optional<UserName> user;
	
	private TemporarySessionData(
			final Operation op,
			final UUID id,
			final Instant created,
			final Instant expires,
			final Optional<Set<RemoteIdentity>> identities,
			final Optional<UserName> user,
			final Optional<String> error,
			final Optional<ErrorType> errorType) {
		this.op = op;
		this.id = id;
		this.created = created;
		this.expires = expires;
		this.identities = identities;
		this.user = user;
		this.error = error;
		this.errorType = errorType;
	}

	/** Get the operation this temporary session data supports.
	 * @return the operation.
	 */
	public Operation getOperation() {
		return op;
	}
	
	/** Get the ID of the temporary session data.
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

	/** Get the date of creation for the session data.
	 * @return the creation date.
	 */
	public Instant getCreated() {
		return created;
	}

	/** Get the date the session data expires from the system.
	 * @return the expiration date.
	 */
	public Instant getExpires() {
		return expires;
	}
	
	/** Get the name of the user associated with the session data, if any.
	 * @return the user name.
	 */
	public Optional<UserName> getUser() {
		return user;
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
		result = prime * result + ((op == null) ? 0 : op.hashCode());
		result = prime * result + ((user == null) ? 0 : user.hashCode());
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
		TemporarySessionData other = (TemporarySessionData) obj;
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
		if (op != other.op) {
			return false;
		}
		if (user == null) {
			if (other.user != null) {
				return false;
			}
		} else if (!user.equals(other.user)) {
			return false;
		}
		return true;
	}
	
	/** The operation this session data is associated with.
	 * @author gaprice@lbl.gov
	 *
	 */
	public static enum Operation {
		/** The last step of the login operation, including identities. */
		LOGINIDENTS,
		/** The start of the link operation. */
		LINKSTART,
		/** The last step of the link operation, including identities. */
		LINKIDENTS,
		/** An operation that resulted in an error. */
		ERROR;
	}
	
	/** Create new temporary session data.
	 * @param id the ID of the session data.
	 * @param created when the session data was created.
	 * @param expires when the session data expires from the system.
	 * @return a builder for the session data.
	 */
	public static Builder create(final UUID id, final Instant created, final Instant expires) {
		return new Builder(id, created, expires);
	}
	
	/** Create new temporary session data.
	 * @param id the ID of the session data.
	 * @param created when the session data was created.
	 * @param lifetimeInMS the lifetime of the session data in milliseconds.
	 * @return a builder for the session data.
	 */
	public static Builder create(final UUID id, final Instant created, final long lifetimeInMS) {
		if (lifetimeInMS < 0) {
			throw new IllegalArgumentException("lifetime must be >= 0");
		}
		nonNull(created, "created");
		final Duration d = Duration.ofMillis(lifetimeInMS);
		final Instant expires;
		if (Instant.MAX.minus(d).isBefore(created)) {
			expires = Instant.MAX;
		} else {
			expires = created.plus(d);
		}
		return new Builder(id, created, expires);
	}
	
	/** A builder for temporary session data.
	 * @author gaprice@lbl.gov
	 *
	 */
	public static class Builder {
		
		private final UUID id;
		private final Instant created;
		private final Instant expires;
		private Optional<Set<RemoteIdentity>> identities = Optional.absent();
		private Optional<String> error = Optional.absent();
		private Optional<ErrorType> errorType = Optional.absent();
		private Optional<UserName> user = Optional.absent();
		
		private Builder(final UUID id, final Instant created, final Instant expires) {
			nonNull(id, "id");
			nonNull(created, "created");
			nonNull(expires, "expires");
			if (expires.isBefore(created)) {
				throw new IllegalArgumentException("expires is before created");
			}
			this.id = id;
			this.created = created;
			this.expires = expires;
		}
		
		/** Create temporary session data associated with an error.
		 * @param error the error.
		 * @param errorType the type of error.
		 * @return the temporary session data.
		 */
		public TemporarySessionData error(final String error, final ErrorType errorType) {
			checkStringNoCheckedException(error, "error");
			nonNull(errorType, "errorType");
			return new TemporarySessionData(
					Operation.ERROR, id, created, expires, identities, user,
					Optional.of(error), Optional.of(errorType));
		}
		
		/** Create temporary session data for a login operation where remote identities are
		 * involved.
		 * @param identities the remote identities involved in the login.
		 * @return the temporary session data.
		 */
		public TemporarySessionData login(final Set<RemoteIdentity> identities) {
			return new TemporarySessionData(
					Operation.LOGINIDENTS, id, created, expires, checkIdents(identities), user,
					error, errorType);
		}

		private Optional<Set<RemoteIdentity>> checkIdents(final Set<RemoteIdentity> identities) {
			nonNull(identities, "identities");
			noNulls(identities, "null item in identities");
			if (identities.isEmpty()) {
				throw new IllegalArgumentException("empty identities");
			}
			return Optional.of(Collections.unmodifiableSet(new HashSet<>(identities)));
		}
		
		/** Create temporary session data for the start of a linking operation.
		 * @param userName the user that is performing the linking operation.
		 * @return the temporary session data.
		 */
		public TemporarySessionData link(final UserName userName) {
			nonNull(userName, "userName");
			return new TemporarySessionData(
					Operation.LINKSTART, id, created, expires, identities, Optional.of(userName),
					error, errorType);
		}
		
		/** Create temporary session data for a linking operation when remote identities are
		 * involved.
		 * @param userName the user that is performing the linking operation.
		 * @param identities the remote identities.
		 * @return the temporary session data.
		 */
		public TemporarySessionData link(
				final UserName userName,
				final Set<RemoteIdentity> identities) {
			nonNull(userName, "userName");
			return new TemporarySessionData(
					Operation.LINKIDENTS, id, created, expires, checkIdents(identities),
					Optional.of(userName), error, errorType);
		}
	}
}
