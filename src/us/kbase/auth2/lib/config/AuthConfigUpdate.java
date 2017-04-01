package us.kbase.auth2.lib.config;

import static us.kbase.auth2.lib.Utils.nonNull;
import static us.kbase.auth2.lib.Utils.checkString;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import com.google.common.base.Optional;

import us.kbase.auth2.lib.config.AuthConfig.TokenLifetimeType;
import us.kbase.auth2.lib.exceptions.MissingParameterException;

public class AuthConfigUpdate<T extends ExternalConfig> {
	
	//TODO NOW JAVADOC
	//TODO NOW TEST
	
	public static final ProviderUpdate DEFAULT_PROVIDER_UPDATE = new ProviderUpdate(
			false, false, false);
	
	public static class ProviderUpdate {
	
		final Optional<Boolean> enabled;
		final Optional<Boolean> forceLoginChoice;
		final Optional<Boolean> forceLinkChoice;
		
		public ProviderUpdate(
				final Optional<Boolean> enabled,
				final Optional<Boolean> forceLoginChoice,
				final Optional<Boolean> forceLinkChoice) {
			nonNull(enabled, "enabled");
			nonNull(forceLoginChoice, "forceLoginChoice");
			nonNull(forceLinkChoice, "forceLinkChoice");
			
			this.enabled = enabled;
			this.forceLoginChoice = forceLoginChoice;
			this.forceLinkChoice = forceLinkChoice;
		}
		
		public ProviderUpdate(
				final boolean enabled,
				final boolean forceLoginChoice,
				final boolean forceLinkChoice) {
			this.enabled = Optional.of(enabled);
			this.forceLoginChoice = Optional.of(forceLoginChoice);
			this.forceLinkChoice = Optional.of(forceLinkChoice);
		}

		public Optional<Boolean> getEnabled() {
			return enabled;
		}

		public Optional<Boolean> getForceLoginChoice() {
			return forceLoginChoice;
		}

		public Optional<Boolean> getForceLinkChoice() {
			return forceLinkChoice;
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

	public Optional<Boolean> getLoginAllowed() {
		return loginAllowed;
	}

	public Map<String, ProviderUpdate> getProviders() {
		return providers;
	}

	public Map<TokenLifetimeType, Long> getTokenLifetimeMS() {
		return tokenLifetimeMS;
	}
	
	public Optional<T> getExternalConfig() {
		return external;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
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
	
	public static <T extends ExternalConfig> Builder<T> getBuilder() {
		return new Builder<>();
	}
	
	public static class Builder<T extends ExternalConfig> {
		
		private Optional<Boolean> loginAllowed = Optional.absent();
		private final Map<String, ProviderUpdate> providers = new HashMap<>();
		private final Map<TokenLifetimeType, Long> tokenLifetimeMS = new HashMap<>();
		private Optional<T> external = Optional.absent();
		
		private Builder() {}
		
		public AuthConfigUpdate<T> build() {
			return new AuthConfigUpdate<>(loginAllowed, providers, tokenLifetimeMS, external);
		}
		
		public Builder<T> withLoginAllowed(final boolean nonAdminLoginAllowed) {
			loginAllowed = Optional.of(nonAdminLoginAllowed);
			return this;
		}
		
		public Builder<T> withProviderUpdate(final String provider, final ProviderUpdate update)
				throws MissingParameterException {
			//TODO CODE should consider provider name class
			checkString(provider, "provider");
			nonNull(update, "update");
			providers.put(provider, update);
			return this;
		}
		
		public Builder<T> withTokenLifeTime(
				final TokenLifetimeType lifetimeType,
				final long lifetimeInMillis) {
			nonNull(lifetimeType, "lifetimeType");
			if (lifetimeInMillis < AuthConfig.MIN_TOKEN_LIFE_MS) {
				throw new IllegalArgumentException(String.format(
						"token lifetime must be at least %s ms", AuthConfig.MIN_TOKEN_LIFE_MS));
			}
			tokenLifetimeMS.put(lifetimeType, lifetimeInMillis);
			return this;
		}
		
		public Builder<T> withDefaultTokenLifeTimes() {
			for (final Entry<TokenLifetimeType, Long> e:
					AuthConfig.DEFAULT_TOKEN_LIFETIMES_MS.entrySet()) {
				tokenLifetimeMS.put(e.getKey(), e.getValue());
			}
			return this;
		}
		
		public Builder<T> withExternalConfig(final T config) {
			nonNull(config, "config");
			external = Optional.of(config);
			return this;
		}
	}
}
