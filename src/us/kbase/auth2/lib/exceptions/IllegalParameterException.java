package us.kbase.auth2.lib.exceptions;

/** A parameter has an illegal value.
 * @author gaprice@lbl.gov
 *
 */
@SuppressWarnings("serial")
public class IllegalParameterException extends AuthException {

	public IllegalParameterException(final String message) {
		super(ErrorType.ILLEGAL_PARAMETER, message);
	}

	public IllegalParameterException(
			final ErrorType type,
			final String message) {
		super(type, message);
	}

	public IllegalParameterException(
			final String message,
			final Throwable cause) {
		super(ErrorType.ILLEGAL_PARAMETER, message, cause);
	}
	

	public IllegalParameterException(
			final ErrorType type,
			final String message,
			final Throwable cause) {
		super(type, message, cause);
	}
}
