package us.kbase.test.auth2;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.LinkedList;
import java.util.List;

import us.kbase.auth2.lib.identity.IdentityProvider;
import us.kbase.auth2.lib.identity.IdentityProviderConfig;
import us.kbase.auth2.lib.identity.IdentityProviderFactory;

public class MockIdentityProviderFactory implements IdentityProviderFactory {

	public static final List<IdentityProvider> mocksInOrderOfCreation = new LinkedList<>();
	public static final List<IdentityProviderConfig> configsInOrder = new LinkedList<>();
	
	@Override
	public IdentityProvider configure(final IdentityProviderConfig cfg) {
		configsInOrder.add(cfg);
		final IdentityProvider prov = mock(IdentityProvider.class);
		final String provname = "prov" + (mocksInOrderOfCreation.size() + 1);
		when(prov.getProviderName()).thenReturn(provname);
		mocksInOrderOfCreation.add(prov);
		return prov;
	}
}
