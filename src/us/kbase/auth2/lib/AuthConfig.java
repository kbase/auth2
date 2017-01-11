package us.kbase.auth2.lib;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/** Contains the configuration of the authentication instance. This class can be used both to
 * report the current state of the configuration and request changes to the configuration.
 * @author gaprice@lbl.gov
 *
 */
public class AuthConfig {

	//TODO TEST
	
	/* might want to have separate current config state classes and config
	 * change classes. Try with the conflated semantics for now.
	 */
	
	private static final int MIN_TOKEN_LIFE = 60 * 1000;
	
	/** Default configuration for a identity provider. */
	public static final ProviderConfig DEFAULT_PROVIDER_CONFIG =
			new ProviderConfig(false, false);
	
	/** Default for whether non-admin logins are allowed. */
	public static final boolean DEFAULT_LOGIN_ALLOWED = false;
	
	/** Default lifetimes for the various token types. */
	public static final Map<TokenLifetimeType, Long> DEFAULT_TOKEN_LIFETIMES_MS;
	static {
		final Map<TokenLifetimeType, Long> m = new HashMap<>();
		m.put(TokenLifetimeType.EXT_CACHE,			   5 * 60 * 1000L);
		m.put(TokenLifetimeType.LOGIN,		14 * 24 * 60 * 60 * 1000L);
		m.put(TokenLifetimeType.DEV,		90 * 24 * 60 * 60 * 1000L);
		m.put(TokenLifetimeType.SERV, 99_999_999_999L * 24 * 60 * 60 * 1000L);
		DEFAULT_TOKEN_LIFETIMES_MS = Collections.unmodifiableMap(m);
	}

	/** A token lifetime type. 
	 * @author gaprice@lbl.gov
	 *
	 */
	public static enum TokenLifetimeType {
		
		/** Lifetime type for a login token. */
		LOGIN,
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
		
		private final Boolean enabled;
		private final Boolean forceLinkChoice;
		
		/** Create a provider config.
		 * @param enabled whether the provider is enabled. True if so, false if not, null if no
		 * change should be applied.
		 * @param forceLinkChoice if false, an account link will proceed immediately if the
		 * provider only returns a single account. If true, the authentication will return a list
		 * of choices for linking populated with all the accounts returned from the provider,
		 * regardless of the number of accounts. Null indicates no change should be applied.
		 */
		public ProviderConfig(
				final Boolean enabled,
				final Boolean forceLinkChoice) {
			super();
			this.enabled = enabled;
			this.forceLinkChoice = forceLinkChoice;
		}

		/** Returns whether this provider is enabled.
		 * @return true for enabled, false for not, null for no change.
		 */
		public Boolean isEnabled() {
			return enabled;
		}

		/** Returns whether the authorization instance will always return a list of account choices
		 * when linking accounts, regardless of the size of the list.
		 * @return true if a list is always returned, false if the link proceeds immediately if
		 * only one account is available for linking, null for no change.
		 */
		public Boolean isForceLinkChoice() {
			return forceLinkChoice;
		}

		@Override
		public String toString() {
			StringBuilder builder = new StringBuilder();
			builder.append("ProviderConfig [enabled=");
			builder.append(enabled);
			builder.append(", forceLinkChoice=");
			builder.append(forceLinkChoice);
			builder.append("]");
			return builder.toString();
		}
	}
	
	private final Boolean loginAllowed;
	private final Map<String, ProviderConfig> providers;
	private final Map<TokenLifetimeType, Long> tokenLifetimeMS;
	
	/** Create an authentication configuration.
	 * @param loginAllowed true if non-admin logins are allowed, false if not, or null if no
	 * changes should be made.
	 * @param providers the names of providers to be used mapped to their configuration. If a
	 * provider is missing from the map no changes will be made to their configuration.
	 * @param tokenLifetimeMS the lifetimes of the various token types. If a lifetime type is
	 * missing from the map no changes will be made to its configuration.
	 */
	public AuthConfig(
			final Boolean loginAllowed,
			Map<String, ProviderConfig> providers,
			Map<TokenLifetimeType, Long> tokenLifetimeMS) {
		// nulls indicate no value or no change depending on context	
		if (providers == null) {
			providers = new HashMap<>();
		}
		for (final String p: providers.keySet()) {
			if (p == null || p.isEmpty()) {
				throw new IllegalArgumentException("provider names cannot be null or empty");
			}
			if (providers.get(p) == null) {
				throw new NullPointerException("Provider config cannot be null");
			}
		}
		if (tokenLifetimeMS == null) {
			tokenLifetimeMS = new HashMap<>();
		}
		for (final TokenLifetimeType t: tokenLifetimeMS.keySet()) {
			if (t == null) {
				throw new NullPointerException("null key in token life time map");
			}
			if (tokenLifetimeMS.get(t) < MIN_TOKEN_LIFE) {
				throw new IllegalArgumentException(String.format(
						"token lifetimes must be at least %s ms", MIN_TOKEN_LIFE));
			}
		}
		this.loginAllowed = loginAllowed;
		this.providers = Collections.unmodifiableMap(new HashMap<>(providers));
		this.tokenLifetimeMS = Collections.unmodifiableMap(new HashMap<>(tokenLifetimeMS));
	}

	/** Returns whether non-admin logins are allowed, or null if no change is to be applied to the
	 * configuration.
	 * @return whether non-admin logins are allowed.
	 */
	public Boolean isLoginAllowed() {
		return loginAllowed;
	}

	/** Returns the providers in this configuration with their configurations.
	 * @return the providers in this configuration.
	 */
	public Map<String, ProviderConfig> getProviders() {
		return providers;
	}

	/** Returns the lifetimes for each token type defined in this configuration.
	 * @return the lifetimes for each token type.
	 */
	public Map<TokenLifetimeType, Long> getTokenLifetimeMS() {
		return tokenLifetimeMS;
	}
	
	/** Get a lifetime for a particular token type.
	 * @param type the type of token for which to get a lifetime.
	 * @return the life time of the token. If the token lifetime was not included in the lifetime
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
	 * @throws IllegalArgumentException if the provider is not contained in this configuration.
	 */
	public ProviderConfig getProviderConfig(final String provider) {
		if (!providers.containsKey(provider)) {
			throw new IllegalArgumentException("No such provider: " +
					provider);
		}
		return providers.get(provider);
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("AuthConfig [loginAllowed=");
		builder.append(loginAllowed);
		builder.append(", providers=");
		builder.append(providers);
		builder.append(", tokenLifetimeMS=");
		builder.append(tokenLifetimeMS);
		builder.append("]");
		return builder.toString();
	}
}
