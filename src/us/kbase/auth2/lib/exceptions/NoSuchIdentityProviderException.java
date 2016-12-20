package us.kbase.auth2.lib.exceptions;

/** Thrown when the requested identity provider is not supported.
 * @author gaprice@lbl.gov 
 */
@SuppressWarnings("serial")
public class NoSuchIdentityProviderException extends AuthenticationException {
	
	public NoSuchIdentityProviderException(final String message) {
		super(ErrorType.NO_SUCH_IDENT_PROV, message);
	}
}
