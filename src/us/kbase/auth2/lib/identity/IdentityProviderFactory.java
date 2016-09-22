package us.kbase.auth2.lib.identity;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import us.kbase.auth2.lib.exceptions.NoSuchIdentityProviderException;

public class IdentityProviderFactory {
	
	//TODO TESTS
	//TODO JAVADOC
	
	private static final IdentityProviderFactory instance =
			new IdentityProviderFactory();
	
	private final TreeMap<String, IdentityProvider> providers =
			new TreeMap<>();
	private final Map<String, IdentityProviderConfigurator> configs =
			new HashMap<>();
	
	
	public static IdentityProviderFactory getInstance() {
		return instance;
	}
	
	private IdentityProviderFactory() {}
	
	// note overwrites configs with the same name
	public void register(final IdentityProviderConfigurator conf) {
		if (conf == null) {
			throw new NullPointerException("conf");
		}
		if (conf.getProviderName() == null ||
				conf.getProviderName().isEmpty()) {
			throw new IllegalArgumentException(
					"The configurator name cannot be null or empty");
		}
		configs.put(conf.getProviderName(), conf);
	}
	
	// note overwrites providers with the same name
	public void configure(final IdentityProviderConfig cfg) {
		if (!configs.containsKey(cfg.getIdentityProviderName())) {
			throw new IllegalArgumentException(
					"Register a configurator before attempting to " +
					"configure it");
		}
		providers.put(cfg.getIdentityProviderName(),
				configs.get(cfg.getIdentityProviderName()).configure(cfg));
	}
	
	public IdentityProvider getProvider(final String name)
			throws NoSuchIdentityProviderException {
		if (!providers.containsKey(name)) {
			throw new NoSuchIdentityProviderException(name);
		}
		return providers.get(name);
		
	}
	
	public List<String> getProviders() {
		return Collections.unmodifiableList(new ArrayList<>(
				providers.navigableKeySet()));
	}

}
