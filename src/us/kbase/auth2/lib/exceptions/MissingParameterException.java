package us.kbase.auth2.lib.exceptions;

/** A required parameter was not provided.
 * @author gaprice@lbl.gov
 *
 */
@SuppressWarnings("serial")
public class MissingParameterException extends AuthException {

	public MissingParameterException(String message) {
		super(ErrorType.MISSING_PARAMETER, message);
	}

	public MissingParameterException(String message, Throwable cause) {
		super(ErrorType.MISSING_PARAMETER, message, cause);
	}
}
