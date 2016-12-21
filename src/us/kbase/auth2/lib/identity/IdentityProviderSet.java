package us.kbase.auth2.lib.identity;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import us.kbase.auth2.lib.exceptions.NoSuchIdentityProviderException;

/** A set of identity providers.
 * @author gaprice@lbl.gov
 *
 */
public class IdentityProviderSet {
	
	private final TreeMap<String, IdentityProvider> providers = new TreeMap<>();
	private final Map<String, IdentityProviderConfigurator> configs = new HashMap<>();
	private boolean locked = false;
	
	
	/** Create an identity provider set. */
	public IdentityProviderSet() {}
	
	/** Register an identity provider configurator. A configurator must be registered before a 
	 * provider can be configured. Registering a configurator with the same provider name as a
	 * previously registered configurator overwrites the old configurator.
	 * @param conf the configurator.
	 */
	public void register(final IdentityProviderConfigurator conf) {
		if (conf == null) {
			throw new NullPointerException("conf");
		}
		if (conf.getProviderName() == null || conf.getProviderName().trim().isEmpty()) {
			throw new IllegalArgumentException("The configurator name cannot be null or empty");
		}
		configs.put(conf.getProviderName(), conf);
	}
	
	/** Configure an identity provider. The configuration and configurator are matched by the 
	 * provider name. Reconfiguring an identity provider replaces the old instance of the identity
	 * provider. 
	 * @param cfg the identity provider configuration.
	 */
	public void configure(final IdentityProviderConfig cfg) {
		if (locked) {
			throw new IllegalStateException("Factory is locked");
		}
		if (cfg == null) {
			throw new NullPointerException("cfg");
		}
		if (!configs.containsKey(cfg.getIdentityProviderName())) {
			throw new IllegalStateException("Register a configurator for identity provider " + 
					cfg.getIdentityProviderName() + " before attempting to configure it");
		}
		providers.put(cfg.getIdentityProviderName(),
				configs.get(cfg.getIdentityProviderName()).configure(cfg));
	}
	
	/** Get a provider from the provider name.
	 * @param name the provider name.
	 * @return an identity provider.
	 * @throws NoSuchIdentityProviderException if no provider exists that has the given name.
	 */
	public IdentityProvider getProvider(final String name)
			throws NoSuchIdentityProviderException {
		if (name == null) {
			throw new NoSuchIdentityProviderException("Provider name cannot be null");
		}
		if (!providers.containsKey(name)) {
			throw new NoSuchIdentityProviderException(name);
		}
		return providers.get(name);
		
	}
	
	/** Returns a sorted list of the currently configured providers.
	 * @return a list of the providers.
	 */
	public List<String> getProviders() {
		return new ArrayList<>(providers.navigableKeySet());
	}

	/** Locks this provider set, preventing any more configuration events - thus, the currently
	 * configured identity providers are rendered immutable.
	 * 
	 * Configurators may still be registered, but this has no effect since configuration events
	 * are prevented.
	 */
	public void lock() {
		locked = true;
	}
	
	/** Check if this provider set is locked.
	 * @return true if the provider set is locked, false otherwise.
	 */
	public boolean isLocked() {
		return locked;
	}

}
