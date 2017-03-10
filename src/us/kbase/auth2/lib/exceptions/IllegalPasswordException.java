package us.kbase.auth2.lib.exceptions;

/** Thrown when a provided password for local user is invalid.
 * @author mwsneddon@lbl.gov 
 */
@SuppressWarnings("serial")
public class IllegalPasswordException extends AuthException {
	public IllegalPasswordException(final String message) {
		super(ErrorType.ILLEGAL_PASSWORD, message);
	}
}