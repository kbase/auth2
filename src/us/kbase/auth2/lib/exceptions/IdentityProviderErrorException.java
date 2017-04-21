package us.kbase.auth2.lib.exceptions;

/** Thrown when a provider reported an error to auth instance when returning from the OAuth2 flow.
 * @author gaprice@lbl.gov 
 */
@SuppressWarnings("serial")
public class IdentityProviderErrorException extends AuthenticationException {
	
	public IdentityProviderErrorException(final String message) {
		super(ErrorType.ID_PROVIDER_ERROR, message);
	}
}
