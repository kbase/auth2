package us.kbase.auth2.lib.exceptions;

/** Thrown when trying to retrieve or delete a non-existent token.
 * @author gaprice@lbl.gov 
 */
@SuppressWarnings("serial")
public class NoSuchTokenException extends NoDataException {
	
	public NoSuchTokenException(final String message) {
		super(ErrorType.NO_SUCH_TOKEN, message);
	}
	
	public NoSuchTokenException(final String message, final Throwable cause) {
		super(ErrorType.NO_SUCH_TOKEN, message, cause);
	}
}
