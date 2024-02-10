package us.kbase.test.auth2;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.HashMap;
import java.util.Map;

import us.kbase.auth2.lib.identity.IdentityProvider;
import us.kbase.auth2.lib.identity.IdentityProviderConfig;
import us.kbase.auth2.lib.identity.IdentityProviderFactory;

public class MockIdentityProviderFactory implements IdentityProviderFactory {

	public static final Map<String, IdentityProvider> MOCKS = new HashMap<>();
	public static final Map<String, IdentityProviderConfig> CONFIGS = new HashMap<>();
	
	@Override
	public IdentityProvider configure(final IdentityProviderConfig cfg) {
		final IdentityProvider prov = mock(IdentityProvider.class);
		final String provname = "prov" + (MOCKS.size() + 1);
		when(prov.getProviderName()).thenReturn(provname);
		when(prov.getEnvironments()).thenReturn(cfg.getEnvironments());
		MOCKS.put(provname, prov);
		CONFIGS.put(provname, cfg);
		return prov;
	}
}
