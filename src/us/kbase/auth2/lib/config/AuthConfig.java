package us.kbase.auth2.lib.config;

import static us.kbase.auth2.lib.Utils.nonNull;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;

import us.kbase.auth2.lib.exceptions.NoSuchIdentityProviderException;

/** Contains the configuration of the authentication instance.
 * @author gaprice@lbl.gov
 *
 */
public class AuthConfig {

	public static final int MIN_TOKEN_LIFE_MS = 60 * 1000;
	
	/** Default for whether non-admin logins are allowed. */
	public static final boolean DEFAULT_LOGIN_ALLOWED = false;
	
	/** Default lifetimes for the various token types in milliseconds. */
	public static final Map<TokenLifetimeType, Long> DEFAULT_TOKEN_LIFETIMES_MS;
	static {
		final Map<TokenLifetimeType, Long> m = new HashMap<>();
		m.put(TokenLifetimeType.EXT_CACHE,			   5 * 60 * 1000L);
		m.put(TokenLifetimeType.AGENT,		 7 * 24 * 60 * 60 * 1000L);
		m.put(TokenLifetimeType.LOGIN,		14 * 24 * 60 * 60 * 1000L);
		m.put(TokenLifetimeType.DEV,		90 * 24 * 60 * 60 * 1000L);
		// this is set so absurdly low because some other, lesser languages can't represent
		// anything much bigger
		m.put(TokenLifetimeType.SERV, 100_000_000L * 24 * 60 * 60 * 1000L);
		DEFAULT_TOKEN_LIFETIMES_MS = Collections.unmodifiableMap(m);
	}

	/** A token lifetime type. 
	 * @author gaprice@lbl.gov
	 *
	 */
	public static enum TokenLifetimeType {
		
		/** Lifetime type for a login token. */
		LOGIN,
		/** Lifetime type for an agent token. */
		AGENT,
		/** Lifetime type for a developer token. */
		DEV,
		/** Lifetime type for a server token. */
		SERV,
		/** Lifetime type for a token in an external cache. */
		EXT_CACHE;
	}
	
	/** Configures the authentication instance's behavior with regard to a specific identity
	 * provider.
	 * @author gaprice@lbl.gov
	 *
	 */
	public static class ProviderConfig {
		
		private final boolean enabled;
		private final boolean forceLoginChoice;
		private final boolean forceLinkChoice;
		
		/** Create a provider config.
		 * @param enabled whether the provider is enabled.
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
		public ProviderConfig(
				final boolean enabled,
				final boolean forceLoginChoice,
				final boolean forceLinkChoice) {
			super();
			this.enabled = enabled;
			this.forceLinkChoice = forceLinkChoice;
			this.forceLoginChoice = forceLoginChoice;
		}

		/** Returns whether this provider is enabled.
		 * @return true for enabled, false otherwise.
		 */
		public boolean isEnabled() {
			return enabled;
		}
		
		/** Returns whether the authorization instance will always return a list of account choices
		 * when logging in, regardless of the size of the list.
		 * @return true if a list is always returned or false if the login proceeds immediately if
		 * only one account is available for login.
		 */
		public boolean isForceLoginChoice() {
			return forceLoginChoice;
		}

		/** Returns whether the authorization instance will always return a list of account choices
		 * when linking accounts, regardless of the size of the list.
		 * @return true if a list is always returned or false if the link proceeds immediately if
		 * only one account is available for linking.
		 */
		public boolean isForceLinkChoice() {
			return forceLinkChoice;
		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + (enabled ? 1231 : 1237);
			result = prime * result + (forceLinkChoice ? 1231 : 1237);
			result = prime * result + (forceLoginChoice ? 1231 : 1237);
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
			ProviderConfig other = (ProviderConfig) obj;
			if (enabled != other.enabled) {
				return false;
			}
			if (forceLinkChoice != other.forceLinkChoice) {
				return false;
			}
			if (forceLoginChoice != other.forceLoginChoice) {
				return false;
			}
			return true;
		}

		@Override
		public String toString() {
			StringBuilder builder = new StringBuilder();
			builder.append("ProviderConfig [enabled=");
			builder.append(enabled);
			builder.append(", forceLoginChoice=");
			builder.append(forceLoginChoice);
			builder.append(", forceLinkChoice=");
			builder.append(forceLinkChoice);
			builder.append("]");
			return builder.toString();
		}
	}
	
	private final boolean loginAllowed;
	private final Map<String, ProviderConfig> providers;
	private final Map<TokenLifetimeType, Long> tokenLifetimeMS;
	
	/** Create an authentication configuration.
	 * @param loginAllowed true if non-admin logins are allowed, false otherwise.
	 * @param providers the names of providers to be used mapped to their configuration.
	 * @param tokenLifetimeMS the lifetimes of the various token types in milliseconds.
	 */
	public AuthConfig(
			final boolean loginAllowed,
			Map<String, ProviderConfig> providers,
			Map<TokenLifetimeType, Long> tokenLifetimeMS) {
		// should probably switch this to a builder
		if (providers == null) {
			providers = new HashMap<>();
		}
		for (final String p: providers.keySet()) {
			if (p == null || p.trim().isEmpty()) {
				throw new IllegalArgumentException("provider names cannot be null or empty");
			}
			nonNull(providers.get(p), String.format("provider config for provider %s is null", p));
		}
		if (tokenLifetimeMS == null) {
			tokenLifetimeMS = new HashMap<>();
		}
		for (final TokenLifetimeType t: tokenLifetimeMS.keySet()) {
			nonNull(t, "null key in token life time map");
			nonNull(tokenLifetimeMS.get(t), String.format("lifetime for key %s is null", t));
			if (tokenLifetimeMS.get(t) < MIN_TOKEN_LIFE_MS) {
				throw new IllegalArgumentException(String.format(
						"lifetime for key %s must be at least %s ms", t, MIN_TOKEN_LIFE_MS));
			}
		}
		this.loginAllowed = loginAllowed;
		this.providers = Collections.unmodifiableMap(new HashMap<>(providers));
		this.tokenLifetimeMS = Collections.unmodifiableMap(new HashMap<>(tokenLifetimeMS));
	}

	/** Returns whether non-admin logins are allowed.
	 * @return whether non-admin logins are allowed.
	 */
	public boolean isLoginAllowed() {
		return loginAllowed;
	}

	/** Returns the providers in this configuration with their configurations.
	 * @return the providers in this configuration.
	 */
	public Map<String, ProviderConfig> getProviders() {
		return providers;
	}

	/** Returns the lifetimes, in milliseconds, for each token type defined in this configuration.
	 * @return the lifetimes for each token type.
	 */
	public Map<TokenLifetimeType, Long> getTokenLifetimeMS() {
		return tokenLifetimeMS;
	}
	
	/** Get a lifetime for a particular token type in milliseconds.
	 * @param type the type of token for which to get a lifetime.
	 * @return the lifetime of the token. If the token lifetime was not included in the lifetime
	 * map upon creation of this configuration, the default lifetime is returned.
	 */
	public Long getTokenLifetimeMS(final TokenLifetimeType type) {
		if (!tokenLifetimeMS.containsKey(type)) {
			return DEFAULT_TOKEN_LIFETIMES_MS.get(type);
		}
		return tokenLifetimeMS.get(type);
	}
	
	/** Get the configuration for a provider.
	 * @param provider the name of the provider.
	 * @return the configuration of the provider.
	 * @throws NoSuchIdentityProviderException if the provider is not contained in this
	 *  configuration.
	 */
	public ProviderConfig getProviderConfig(final String provider)
			throws NoSuchIdentityProviderException {
		if (!providers.containsKey(provider)) {
			throw new NoSuchIdentityProviderException(provider);
		}
		return providers.get(provider);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + (loginAllowed ? 1231 : 1237);
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
		AuthConfig other = (AuthConfig) obj;
		if (loginAllowed != other.loginAllowed) {
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

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("AuthConfig [loginAllowed=");
		builder.append(loginAllowed);
		builder.append(", providers=");
		builder.append(new TreeMap<>(providers));
		builder.append(", tokenLifetimeMS=");
		builder.append(new TreeMap<>(tokenLifetimeMS));
		builder.append("]");
		return builder.toString();
	}
}
