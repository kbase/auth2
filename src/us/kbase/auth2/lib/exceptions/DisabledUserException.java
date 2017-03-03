package us.kbase.auth2.lib.exceptions;

/** Thrown when trying to access a user whose account has been disabled.
 * @author gaprice@lbl.gov 
 */
@SuppressWarnings("serial")
public class DisabledUserException extends UnauthorizedException {
	
	public DisabledUserException(final String message) {
		super(ErrorType.DISABLED, message);
	}
}
