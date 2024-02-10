package us.kbase.auth2.lib.identity;

/** A configuration agent for an identity provider. Given an identity provider configuration,
 * properly creates and configures an identity provider.
 * @author gaprice@lbl.gov
 *
 */
public interface IdentityProviderFactory {
	
	/** Given a configuration, creates an identity provider.
	 * @param cfg the identity provider configuration.
	 * @return the new identity provider.
	 */
	IdentityProvider configure(IdentityProviderConfig cfg);
}
