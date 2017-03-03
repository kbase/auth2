package us.kbase.auth2.lib.exceptions;

/** Base class of all exceptions caused by trying to get data that doesn't
 * exist.
 * @author gaprice@lbl.gov 
 */
@SuppressWarnings("serial")
public class NoDataException extends AuthException {
	
	public NoDataException(final ErrorType err, final String message) {
		super(err, message);
	}
}
