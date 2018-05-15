package us.kbase.test.auth2.service.common;

import us.kbase.auth2.lib.identity.IdentityProvider;
import us.kbase.auth2.lib.identity.IdentityProviderConfig;
import us.kbase.auth2.lib.identity.IdentityProviderFactory;

public class FailOnInstantiation implements IdentityProviderFactory {

	public FailOnInstantiation() {
		throw new IllegalArgumentException("foo");
	}
	
	@Override
	public IdentityProvider configure(IdentityProviderConfig cfg) {
		return null;
	}

	
}
