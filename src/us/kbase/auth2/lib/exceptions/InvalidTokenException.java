package us.kbase.auth2.lib.exceptions;

/** Thrown when the provided token either does not exist in the database or is otherwise
 * invalid.
 * @author gaprice@lbl.gov 
 */
@SuppressWarnings("serial")
public class InvalidTokenException extends AuthenticationException {
	
	public InvalidTokenException() {
		super(ErrorType.INVALID_TOKEN, null);
	}
}
