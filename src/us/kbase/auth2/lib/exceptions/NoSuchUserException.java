package us.kbase.auth2.lib.exceptions;

/** Thrown when trying to access a non-existent user.
 * @author gaprice@lbl.gov 
 */
@SuppressWarnings("serial")
public class NoSuchUserException extends NoDataException {
	
	public NoSuchUserException(final String message) {
		super(ErrorType.NO_SUCH_USER, message);
	}
	
	public NoSuchUserException(final String message, final Throwable cause) {
		super(ErrorType.NO_SUCH_USER, message, cause);
	}
	
	NoSuchUserException(final ErrorType err, final String message) {
		super(err, message);
	}
	
	NoSuchUserException(final ErrorType err, final String message, final Throwable cause) {
		super(err, message, cause);
	}
}
