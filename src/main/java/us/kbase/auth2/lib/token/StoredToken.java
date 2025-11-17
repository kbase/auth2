package us.kbase.auth2.lib.token;

import static java.util.Objects.requireNonNull;

import java.time.Instant;
import java.util.Objects;
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
	private final MFAStatus mfa;
	
	private StoredToken(
			final UUID id,
			final TokenType type,
			final Optional<TokenName> tokenName,
			final UserName userName,
			final TokenCreationContext context,
			final Instant creationDate,
			final Instant expirationDate,
			final MFAStatus mfa
	) {
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
		this.mfa = mfa;
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
	
	/** Get the MFA status of the token.
	 * @return the MFA status.
	 */
	public MFAStatus getMFA() {
		return mfa;
	}
	
	@Override
	public int hashCode() {
		return Objects.hash(
				context, creationDate, expirationDate, id, mfa, tokenName, type, userName
		);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		StoredToken other = (StoredToken) obj;
		return Objects.equals(context, other.context)
				&& Objects.equals(creationDate, other.creationDate)
				&& Objects.equals(expirationDate, other.expirationDate)
				&& Objects.equals(id, other.id)
				&& mfa == other.mfa
				&& Objects.equals(tokenName, other.tokenName)
				&& type == other.type
				&& Objects.equals(userName, other.userName);
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
		
		/** Specify the MFA status; default is {@link MFAStatus#UNKNOWN}.
		 * @param context the MFA status.
		 * @return this builder.
		 */
		OptionalsStep withMFA(MFAStatus mfa);
		
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
		private MFAStatus mfa = MFAStatus.UNKNOWN;
	
		private Builder(final TokenType type, final UUID id, final UserName userName) {
			this.id = requireNonNull(id, "id");
			this.type = requireNonNull(type, "type");
			this.userName = requireNonNull(userName, "userName");;
		}

		@Override
		public OptionalsStep withTokenName(final TokenName tokenName) {
			this.tokenName = Optional.of(requireNonNull(tokenName, "tokenName"));
			return this;
		}
		
		@Override
		public OptionalsStep withNullableTokenName(final TokenName tokenName) {
			this.tokenName = Optional.ofNullable(tokenName);
			return this;
		}
		
		@Override
		public OptionalsStep withContext(final TokenCreationContext context) {
			this.context = requireNonNull(context, "context");
			return this;
		}
		
		@Override
		public OptionalsStep withMFA(final MFAStatus mfa) {
			this.mfa = requireNonNull(mfa, "mfa");
			return this;
		}

		@Override
		public StoredToken build() {
			return new StoredToken(id, type, tokenName, userName, context,
					creationDate, expirationDate, mfa);
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
				final long lifeTimeInMilliseconds) { // TODO CODE check > 0
			this.creationDate = requireNonNull(created, "created");
			this.expirationDate = created.plusMillis(lifeTimeInMilliseconds);
			return this;
		}
	}
}