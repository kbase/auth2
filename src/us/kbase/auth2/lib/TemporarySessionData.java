package us.kbase.auth2.lib;

import static us.kbase.auth2.lib.Utils.checkStringNoCheckedException;
import static us.kbase.auth2.lib.Utils.nonNull;
import static us.kbase.auth2.lib.Utils.noNulls;

import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

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
	private final String oauth2State;
	private final Set<RemoteIdentity> identities;
	private final String error;
	private final ErrorType errorType;
	private final UserName user;
	
	private TemporarySessionData(
			final Operation op,
			final UUID id,
			final Instant created,
			final Instant expires,
			final String oauth2State,
			final Set<RemoteIdentity> identities,
			final UserName user,
			final String error,
			final ErrorType errorType) {
		this.op = op;
		this.id = id;
		this.created = created;
		this.expires = expires;
		this.oauth2State = oauth2State;
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
		return Optional.ofNullable(identities);
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
	
	/** Get the state value for the OAuth2 request associated with this temporary data, if any.
	 * @return the state value.
	 */
	public Optional<String> getOAuth2State() {
		return Optional.ofNullable(oauth2State);
	}
	
	/** Get the name of the user associated with the session data, if any.
	 * @return the user name.
	 */
	public Optional<UserName> getUser() {
		return Optional.ofNullable(user);
	}
	
	/** Returns the error, if any.
	 * @return the error.
	 */
	public Optional<String> getError() {
		return Optional.ofNullable(error);
	}
	
	/** Get the type of the error, if any.
	 * @return the error type.
	 */
	public Optional<ErrorType> getErrorType() {
		return Optional.ofNullable(errorType);
	}
	
	/** Returns true if an error is present.
	 * @return true if an error is present.
	 */
	public boolean hasError() {
		return error != null;
	}

	@Override
	public int hashCode() {
		return Objects.hash(created, error, errorType, expires, id, identities, oauth2State, op, user);
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
		return Objects.equals(created, other.created) && Objects.equals(error, other.error)
				&& errorType == other.errorType && Objects.equals(expires, other.expires)
				&& Objects.equals(id, other.id) && Objects.equals(identities, other.identities)
				&& Objects.equals(oauth2State, other.oauth2State) && op == other.op && Objects.equals(user, other.user);
	}
	
	/** The operation this session data is associated with.
	 * @author gaprice@lbl.gov
	 *
	 */
	public static enum Operation {
		/** The start of the login operation. */
		LOGINSTART,
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
					Operation.ERROR, id, created, expires,
					null, null, null, error, errorType);
		}
		
		/** Create temporary session data for the start of a login operation.
		 * @param oauth2State the OAuth2 session state value.
		 * @return the temporary session data.
		 */
		public TemporarySessionData login(final String oauth2State) {
			checkStringNoCheckedException(oauth2State, "oauth2State");
			return new TemporarySessionData(
					Operation.LOGINSTART, id, created, expires,
					oauth2State, null, null, null, null);
		}
		
		/** Create temporary session data for a login operation where remote identities are
		 * involved.
		 * @param identities the remote identities involved in the login.
		 * @return the temporary session data.
		 */
		public TemporarySessionData login(final Set<RemoteIdentity> identities) {
			return new TemporarySessionData(
					Operation.LOGINIDENTS, id, created, expires,
					null, checkIdents(identities), null, null, null);
		}

		private Set<RemoteIdentity> checkIdents(final Set<RemoteIdentity> identities) {
			nonNull(identities, "identities");
			noNulls(identities, "null item in identities");
			if (identities.isEmpty()) {
				throw new IllegalArgumentException("empty identities");
			}
			return Collections.unmodifiableSet(new HashSet<>(identities));
		}
		
		/** Create temporary session data for the start of a linking operation.
		 * @param oauth2State the OAuth2 session state value.
		 * @param userName the user that is performing the linking operation.
		 * @return the temporary session data.
		 */
		public TemporarySessionData link(final String oauth2State, final UserName userName) {
			checkStringNoCheckedException(oauth2State, "oauth2State");
			nonNull(userName, "userName");
			return new TemporarySessionData(
					Operation.LINKSTART, id, created, expires,
					oauth2State, null, userName, null, null);
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
					Operation.LINKIDENTS, id, created, expires,
					null, checkIdents(identities), userName, null, null);
		}
	}
}
