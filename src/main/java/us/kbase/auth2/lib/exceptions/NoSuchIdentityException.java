package us.kbase.auth2.lib.exceptions;

/** Thrown when a user does not possess the requested identity.
 * @author gaprice@lbl.gov 
 */
@SuppressWarnings("serial")
public class NoSuchIdentityException extends AuthException {
	
	public NoSuchIdentityException(final String message) {
		super(ErrorType.NO_SUCH_IDENTITY, message);
	}
}
