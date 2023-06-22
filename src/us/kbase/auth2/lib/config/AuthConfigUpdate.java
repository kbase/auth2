package us.kbase.auth2.lib.config;

import static java.util.Objects.requireNonNull;
import static us.kbase.auth2.lib.Utils.checkString;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;

import us.kbase.auth2.lib.config.AuthConfig.TokenLifetimeType;
import us.kbase.auth2.lib.exceptions.MissingParameterException;

/** Specifies an update to the authentication configuration.
 * @author gaprice@lbl.gov
 *
 * @param <T> the type of the external configuration class to include in the update.
 */
public class AuthConfigUpdate<T extends ExternalConfig> {
	
	/** The default provider update - not enabled and neither of the force options are active. */
	public static final ProviderUpdate DEFAULT_PROVIDER_UPDATE = new ProviderUpdate(
			false, false, false);
	
	/** An update to an identity provider configuration.
	 * @author gaprice@lbl.gov
	 *
	 */
	public static class ProviderUpdate {
	
		private final Optional<Boolean> enabled;
		private final Optional<Boolean> forceLoginChoice;
		private final Optional<Boolean> forceLinkChoice;
		
		/** Create an update to a provider configuration.
		 * @param enabled true to enable the provider, false to disable, absent to make no change
		 * to the provider configuration.
		 * @param forceLoginChoice if false, an account link will proceed immediately if the
		 * provider only returns a single remote identity and that identity is already linked
		 * to a user account. If true, the Authentication class will return a list of choices for
		 * login or account creation populated with all the accounts returned from the provider,
		 * regardless of the number of accounts. If absent, no change will be made to the provider
		 * configuration.
		 * @param forceLinkChoice if false, an account link will proceed immediately if the
		 * provider only returns a single remote identity. If true, the Authentication class will
		 * return a list of choices for linking populated with all the accounts returned from the
		 * provider, regardless of the number of accounts. If absent, no change will be made to
		 * the provider configuration.
		 */
		public ProviderUpdate(
				final Optional<Boolean> enabled,
				final Optional<Boolean> forceLoginChoice,
				final Optional<Boolean> forceLinkChoice) {
			requireNonNull(enabled, "enabled");
			requireNonNull(forceLoginChoice, "forceLoginChoice");
			requireNonNull(forceLinkChoice, "forceLinkChoice");
			
			this.enabled = enabled;
			this.forceLoginChoice = forceLoginChoice;
			this.forceLinkChoice = forceLinkChoice;
		}
		
		/** Create an update to a provider configuration.
		 * @param enabled true to enable the provider, false to disable.
		 * @param forceLoginChoice if false, an account link will proceed immediately if the
		 * provider only returns a single remote identity and that identity is already linked
		 * to a user account. If true, the Authentication class will return a list of choices for
		 * login or account creation populated with all the accounts returned from the provider,
		 * regardless of the number of accounts.
		 * @param forceLinkChoice if false, an account link will proceed immediately if the
		 * provider only returns a single remote identity. If true, the Authentication class will
		 * return a list of choices for linking populated with all the accounts returned from the
		 * provider, regardless of the number of accounts.
		 */
		public ProviderUpdate(
				final boolean enabled,
				final boolean forceLoginChoice,
				final boolean forceLinkChoice) {
			this.enabled = Optional.of(enabled);
			this.forceLoginChoice = Optional.of(forceLoginChoice);
			this.forceLinkChoice = Optional.of(forceLinkChoice);
		}

		/** Get whether the provider should be enabled or not, or no change should be made.
		 * @return whether the provider should be enabled.
		 */
		public Optional<Boolean> getEnabled() {
			return enabled;
		}

		/** Returns whether the authorization instance will be set to always return a list of
		 * account choices when logging in, regardless of the size of the list, or whether no
		 * change should be made.
		 * @return true if a list is always returned, false if the login proceeds immediately if
		 * only one account is available for login, or absent for no change.
		 */
		public Optional<Boolean> getForceLoginChoice() {
			return forceLoginChoice;
		}

		/** Returns whether the authorization instance will be set to always return a list of
		 * account choices when linking accounts, regardless of the size of the list, or whether
		 * no change should be made.
		 * @return true if a list is always returned, false if the link proceeds immediately if
		 * only one account is available for linking, or absent for no change.
		 */
		public Optional<Boolean> getForceLinkChoice() {
			return forceLinkChoice;
		}
		
		/** Returns true if at least one of the options is present, and therefore an update is
		 * necessary.
		 * @return true if this provider update contains an update.
		 */
		public boolean hasUpdate() {
			return enabled.isPresent() || forceLinkChoice.isPresent() ||
					forceLoginChoice.isPresent();
		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + ((enabled == null) ? 0 : enabled.hashCode());
			result = prime * result + ((forceLinkChoice == null) ? 0 : forceLinkChoice.hashCode());
			result = prime * result + ((forceLoginChoice == null) ? 0 : forceLoginChoice.hashCode());
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
			ProviderUpdate other = (ProviderUpdate) obj;
			if (enabled == null) {
				if (other.enabled != null) {
					return false;
				}
			} else if (!enabled.equals(other.enabled)) {
				return false;
			}
			if (forceLinkChoice == null) {
				if (other.forceLinkChoice != null) {
					return false;
				}
			} else if (!forceLinkChoice.equals(other.forceLinkChoice)) {
				return false;
			}
			if (forceLoginChoice == null) {
				if (other.forceLoginChoice != null) {
					return false;
				}
			} else if (!forceLoginChoice.equals(other.forceLoginChoice)) {
				return false;
			}
			return true;
		}
	}
	
	private final Optional<Boolean> loginAllowed;
	private final Map<String, ProviderUpdate> providers;
	private final Map<TokenLifetimeType, Long> tokenLifetimeMS;
	private final Optional<T> external;
	
	private AuthConfigUpdate(
			final Optional<Boolean> loginAllowed,
			final Map<String, ProviderUpdate> providers,
			final Map<TokenLifetimeType, Long> tokenLifetimeMS,
			final Optional<T> external) {
		this.loginAllowed = loginAllowed;
		this.providers = Collections.unmodifiableMap(providers);
		this.tokenLifetimeMS = Collections.unmodifiableMap(tokenLifetimeMS);
		this.external = external;
	}

	/** Returns whether non-admins should be allowed to log in, or absent for no change.
	 * @return whether non-admin should be allowed to log in.
	 */
	public Optional<Boolean> getLoginAllowed() {
		return loginAllowed;
	}

	/** Returns the set of provider updates to apply to the configuration.
	 * @return the provider updates.
	 */
	public Map<String, ProviderUpdate> getProviders() {
		return providers;
	}

	/** Returns the set of token lifetime updates to apply to the configuration.
	 * @return the token lifetime updates.
	 */
	public Map<TokenLifetimeType, Long> getTokenLifetimeMS() {
		return tokenLifetimeMS;
	}
	
	/** Returns the external configuration updates to apply to the configuration.
	 * @return the external configuration updates.
	 */
	public Optional<T> getExternalConfig() {
		return external;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((external == null) ? 0 : external.hashCode());
		result = prime * result + ((loginAllowed == null) ? 0 : loginAllowed.hashCode());
		result = prime * result + ((providers == null) ? 0 : providers.hashCode());
		result = prime * result + ((tokenLifetimeMS == null) ? 0 : tokenLifetimeMS.hashCode());
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
		AuthConfigUpdate<?> other = (AuthConfigUpdate<?>) obj;
		if (external == null) {
			if (other.external != null) {
				return false;
			}
		} else if (!external.equals(other.external)) {
			return false;
		}
		if (loginAllowed == null) {
			if (other.loginAllowed != null) {
				return false;
			}
		} else if (!loginAllowed.equals(other.loginAllowed)) {
			return false;
		}
		if (providers == null) {
			if (other.providers != null) {
				return false;
			}
		} else if (!providers.equals(other.providers)) {
			return false;
		}
		if (tokenLifetimeMS == null) {
			if (other.tokenLifetimeMS != null) {
				return false;
			}
		} else if (!tokenLifetimeMS.equals(other.tokenLifetimeMS)) {
			return false;
		}
		return true;
	}
	
	/** Get a builder for an authorization configuration update.
	 * @param <T> the type of the external configuration class to include in the update, if any.
	 * @return a builder.
	 */
	public static <T extends ExternalConfig> Builder<T> getBuilder() {
		return new Builder<>();
	}
	
	/** A Builder for an authorization configuration update.
	 * @author gaprice@lbl.gov
	 *
	 * @param <T> the type of the external configuration class to include in the update, if any.
	 */
	public static class Builder<T extends ExternalConfig> {
		
		private Optional<Boolean> loginAllowed = Optional.empty();
		private final Map<String, ProviderUpdate> providers = new HashMap<>();
		private final Map<TokenLifetimeType, Long> tokenLifetimeMS = new HashMap<>();
		private Optional<T> external = Optional.empty();
		
		private Builder() {}
		
		/** Build the update.
		 * @return the update.
		 */
		public AuthConfigUpdate<T> build() {
			return new AuthConfigUpdate<>(loginAllowed, providers, tokenLifetimeMS, external);
		}
		
		/** Set whether non admin logins should be allowed.
		 * @param nonAdminLoginAllowed true to allow, false to disallow.
		 * @return this builder.
		 */
		public Builder<T> withLoginAllowed(final boolean nonAdminLoginAllowed) {
			loginAllowed = Optional.of(nonAdminLoginAllowed);
			return this;
		}
		
		/** Set whether non admin logins should be allowed.
		 * @param nonAdminLoginAllowed true to allow, false to disallow, null for no change.
		 * @return this builder.
		 */
		public Builder<T> withNullableLoginAllowed(final Boolean nonAdminLoginAllowed) {
			loginAllowed = Optional.ofNullable(nonAdminLoginAllowed);
			return this;
		}
		
		/** Add a provider update to the configuration update. Adding an update for the same 
		 * provider twice will overwrite the previous update.
		 * @param provider the provider to which the update will apply.
		 * @param update the update for the provider.
		 * @return this builder.
		 * @throws MissingParameterException if the provider name is null or empty.
		 */
		public Builder<T> withProviderUpdate(final String provider, final ProviderUpdate update)
				throws MissingParameterException {
			//TODO ZLATER CODE should consider provider name class
			checkString(provider, "provider");
			requireNonNull(update, "update");
			providers.put(provider, update);
			return this;
		}
		
		/** Add a token lifetime to the configuration update.
		 * @param lifetimeType the type of token lifetime to add to the configuration update.
		 * @param lifetimeInMillis the new lifetime.
		 * @return this builder.
		 */
		public Builder<T> withTokenLifeTime(
				final TokenLifetimeType lifetimeType,
				final long lifetimeInMillis) {
			requireNonNull(lifetimeType, "lifetimeType");
			if (lifetimeInMillis < AuthConfig.MIN_TOKEN_LIFE_MS) {
				throw new IllegalArgumentException(String.format(
						"token lifetime must be at least %s ms", AuthConfig.MIN_TOKEN_LIFE_MS));
			}
			tokenLifetimeMS.put(lifetimeType, lifetimeInMillis);
			return this;
		}
		
		/** Adds the default token lifetimes to this builder. Default token lifetimes are
		 * specified in {@link AuthConfig#DEFAULT_TOKEN_LIFETIMES_MS}.
		 * @return this bulider.
		 */
		public Builder<T> withDefaultTokenLifeTimes() {
			for (final Entry<TokenLifetimeType, Long> e:
					AuthConfig.DEFAULT_TOKEN_LIFETIMES_MS.entrySet()) {
				tokenLifetimeMS.put(e.getKey(), e.getValue());
			}
			return this;
		}
		
		/** Adds an external configuration update.
		 * @param config the external configuration update.
		 * @return this builder.
		 */
		public Builder<T> withExternalConfig(final T config) {
			requireNonNull(config, "config");
			external = Optional.of(config);
			return this;
		}
	}
}
