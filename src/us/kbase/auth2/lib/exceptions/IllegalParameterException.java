package us.kbase.auth2.lib.exceptions;

/** A parameter has an illegal value.
 * @author gaprice@lbl.gov
 *
 */
@SuppressWarnings("serial")
public class IllegalParameterException extends AuthException {

	public IllegalParameterException(String message) {
		super(ErrorType.ILLEGAL_PARAMETER, message);
	}

	public IllegalParameterException(String message, Throwable cause) {
		super(ErrorType.ILLEGAL_PARAMETER, message, cause);
	}
}
