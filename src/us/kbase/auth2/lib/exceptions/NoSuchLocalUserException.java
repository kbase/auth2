package us.kbase.auth2.lib.exceptions;

/** Thrown when trying to access a non-existent local user.
 * @author gaprice@lbl.gov 
 */
@SuppressWarnings("serial")
public class NoSuchLocalUserException extends NoSuchUserException {
	
	public NoSuchLocalUserException(final String message) {
		super(ErrorType.NO_SUCH_LOCAL_USER, message);
	}
	
	public NoSuchLocalUserException(final String message, final Throwable cause) {
		super(ErrorType.NO_SUCH_LOCAL_USER, message, cause);
	}
}
