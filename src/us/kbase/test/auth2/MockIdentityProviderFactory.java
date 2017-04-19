package us.kbase.test.auth2;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import us.kbase.auth2.lib.identity.IdentityProvider;
import us.kbase.auth2.lib.identity.IdentityProviderConfig;
import us.kbase.auth2.lib.identity.IdentityProviderFactory;

public class MockIdentityProviderFactory implements IdentityProviderFactory {

	public static final Map<String, IdentityProvider> mocks = new HashMap<>();
	public static final List<IdentityProviderConfig> configs = new LinkedList<>();
	
	@Override
	public IdentityProvider configure(final IdentityProviderConfig cfg) {
		configs.add(cfg);
		final IdentityProvider prov = mock(IdentityProvider.class);
		final String provname = "prov" + (mocks.size() + 1);
		when(prov.getProviderName()).thenReturn(provname);
		mocks.put(provname, prov);
		return prov;
	}
}
