package us.kbase.auth2.lib.exceptions;

/** Base class of all exceptions caused by an authorization failure.
 * @author gaprice@lbl.gov 
 */
@SuppressWarnings("serial")
public class UnauthorizedException extends AuthException {
	
	
	public UnauthorizedException(final ErrorType err) {
		super(err, null);
	}
	
	public UnauthorizedException(final ErrorType err, final String message) {
		super(err, message);
	}
}
