package us.kbase.auth2.lib.exceptions;

/** Thrown when a username and password do not match.
 * @author gaprice@lbl.gov 
 */
@SuppressWarnings("serial")
public class PasswordMismatchException extends AuthenticationException {
	
	public PasswordMismatchException(final String message) {
		super(ErrorType.PASSWORD_MISMATCH, message);
	}
}
