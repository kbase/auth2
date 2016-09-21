package us.kbase.auth2.lib.identity;

public interface IdentityProviderConfigurator {
	
	//TODO JAVADOC
	
	IdentityProvider configure(IdentityProviderConfig cfg);
	String getProviderName();
}
