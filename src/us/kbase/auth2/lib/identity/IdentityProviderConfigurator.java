package us.kbase.auth2.lib.identity;

/** A configuration agent for an identity provider. Given an identity provider configuration,
 * properly creates and configures an identity provider.
 * @author gaprice@lbl.gov
 *
 */
public interface IdentityProviderConfigurator {
	
	/** Given a configuration, creates an identity provider.
	 * @param cfg the identity provider configuration.
	 * @return the new identity provider.
	 */
	IdentityProvider configure(IdentityProviderConfig cfg);
	
	/** Get the name of the identity provider this configurator is able to configure.
	 * @return the identity provider name.
	 */
	String getProviderName();
}
