package us.kbase.auth2.lib.token;

import static java.util.Objects.requireNonNull;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import us.kbase.auth2.lib.TokenCreationContext;
import us.kbase.auth2.lib.UserName;

/** A token associated with a user stored in the authentication storage system.
 * 
 * @author gaprice@lbl.gov
 *
 */
public class StoredToken {
	
	private final UUID id;
	private final TokenType type;
	private final Optional<TokenName> tokenName;
	private final TokenCreationContext context;
	private final UserName userName;
	private final Instant creationDate;
	private final Instant expirationDate;
	
	private StoredToken(
			final UUID id,
			final TokenType type,
			final Optional<TokenName> tokenName,
			final UserName userName,
			final TokenCreationContext context,
			final Instant creationDate,
			final Instant expirationDate) {
		// this stuff is here just in case naughty users use casting to skip a builder step
		requireNonNull(creationDate, "created");
		// no way to test this one
		requireNonNull(expirationDate, "expires");
		this.type = type;
		this.tokenName = tokenName;
		this.context = context;
		this.userName = userName;
		this.expirationDate = expirationDate;
		this.creationDate = creationDate;
		this.id = id;
	}

	/** Get the type of the token.
	 * @return the token type.
	 */
	public TokenType getTokenType() {
		return type;
	}
	
	/** Get the token's ID.
	 * @return the ID.
	 */
	public UUID getId() {
		return id;
	}
	
	/** Get the name of the token, or absent if it is unnamed.
	 * @return the name of the token.
	 */
	public Optional<TokenName> getTokenName() {
		return tokenName;
	}

	/** Get the name of the user that possesses this token.
	 * @return the user name.
	 */
	public UserName getUserName() {
		return userName;
	}
	
	/** Get the context in which this token was created.
	 * @return the creation context.
	 */
	public TokenCreationContext getContext() {
		return context;
	}

	/** Get the date the token was created.
	 * @return the creation date.
	 */
	public Instant getCreationDate() {
		return creationDate;
	}

	/** Get the date the token expires.
	 * @return the expiration date.
	 */
	public Instant getExpirationDate() {
		return expirationDate;
	}
	
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((context == null) ? 0 : context.hashCode());
		result = prime * result + ((creationDate == null) ? 0 : creationDate.hashCode());
		result = prime * result + ((expirationDate == null) ? 0 : expirationDate.hashCode());
		result = prime * result + ((id == null) ? 0 : id.hashCode());
		result = prime * result + ((tokenName == null) ? 0 : tokenName.hashCode());
		result = prime * result + ((type == null) ? 0 : type.hashCode());
		result = prime * result + ((userName == null) ? 0 : userName.hashCode());
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
		StoredToken other = (StoredToken) obj;
		if (context == null) {
			if (other.context != null) {
				return false;
			}
		} else if (!context.equals(other.context)) {
			return false;
		}
		if (creationDate == null) {
			if (other.creationDate != null) {
				return false;
			}
		} else if (!creationDate.equals(other.creationDate)) {
			return false;
		}
		if (expirationDate == null) {
			if (other.expirationDate != null) {
				return false;
			}
		} else if (!expirationDate.equals(other.expirationDate)) {
			return false;
		}
		if (id == null) {
			if (other.id != null) {
				return false;
			}
		} else if (!id.equals(other.id)) {
			return false;
		}
		if (tokenName == null) {
			if (other.tokenName != null) {
				return false;
			}
		} else if (!tokenName.equals(other.tokenName)) {
			return false;
		}
		if (type != other.type) {
			return false;
		}
		if (userName == null) {
			if (other.userName != null) {
				return false;
			}
		} else if (!userName.equals(other.userName)) {
			return false;
		}
		return true;
	}
	
	/** Get a builder for a StoredToken.
	 * @param type the type of the token.
	 * @param id the token's ID.
	 * @param user the user name associated with the token.
	 * @return a builder.
	 */
	public static LifeStep getBuilder(final TokenType type, final UUID id, final UserName user) {
		return new Builder(type, id, user);
	}
	
	/** A step in the StoredToken builder for specifying the token's lifetime.
	 * @author gaprice@lbl.gov
	 *
	 */
	public interface LifeStep {
		
		/** Specify the lifetime for the token.
		 * @param created the date the token was created.
		 * @param expires the date the token expires.
		 * @return the next step of the builder.
		 */
		OptionalsStep withLifeTime(Instant created, Instant expires);
		
		/** Specify the lifetime for the token.
		 * @param created the date the token was created.
		 * @param lifeTimeInMilliseconds the lifetime of the token in milliseconds.
		 * @return the next step of the builder.
		 */
		OptionalsStep withLifeTime(Instant created, long lifeTimeInMilliseconds);
	}
	
	/** A step in the StoredToken builder for specifying optional information and completing the
	 * build.
	 * @author gaprice@lbl.gov
	 *
	 */
	public interface OptionalsStep {
		
		/** Specify the token's name.
		 * @param tokenName the token's name.
		 * @return this builder.
		 */
		OptionalsStep withTokenName(TokenName tokenName);
		
		/** Specify the token's name, and allow null input.
		 * @param tokenName the token's name, or null for no name.
		 * @return this builder.
		 */
		OptionalsStep withNullableTokenName(TokenName tokenName);
		
		/** Specify the token creation context.
		 * @param context the token creation context.
		 * @return this builder.
		 */
		OptionalsStep withContext(TokenCreationContext context);
		
		/** Build the token.
		 * @return a new StoredToken.
		 */
		StoredToken build();
	}
	
	private static class Builder implements LifeStep, OptionalsStep {
		
		private final UUID id;
		private final TokenType type;
		private Optional<TokenName> tokenName = Optional.empty();
		private TokenCreationContext context = TokenCreationContext.getBuilder().build();
		private final UserName userName;
		private Instant creationDate;
		private Instant expirationDate;
	
		private Builder(final TokenType type, final UUID id, final UserName userName) {
			requireNonNull(type, "type");
			requireNonNull(id, "id");
			requireNonNull(userName, "userName");
			this.id = id;
			this.type = type;
			this.userName = userName;
		}

		@Override
		public OptionalsStep withTokenName(final TokenName tokenName) {
			requireNonNull(tokenName, "tokenName");
			this.tokenName = Optional.of(tokenName);
			return this;
		}
		
		@Override
		public OptionalsStep withNullableTokenName(final TokenName tokenName) {
			this.tokenName = Optional.ofNullable(tokenName);
			return this;
		}
		
		@Override
		public OptionalsStep withContext(final TokenCreationContext context) {
			requireNonNull(context, "context");
			this.context = context;
			return this;
		}

		@Override
		public StoredToken build() {
			return new StoredToken(id, type, tokenName, userName, context,
					creationDate, expirationDate);
		}

		@Override
		public OptionalsStep withLifeTime(final Instant created, final Instant expires) {
			requireNonNull(created, "created");
			requireNonNull(expires, "expires");
			if (created.isAfter(expires)) {
				throw new IllegalArgumentException("expires must be > created");
			}
			this.creationDate = created;
			this.expirationDate = expires;
			return this;
		}

		@Override
		public OptionalsStep withLifeTime(
				final Instant created,
				final long lifeTimeInMilliseconds) {
			requireNonNull(created, "created");
			this.creationDate = created;
			this.expirationDate = created.plusMillis(lifeTimeInMilliseconds);
			return this;
		}
	}
}