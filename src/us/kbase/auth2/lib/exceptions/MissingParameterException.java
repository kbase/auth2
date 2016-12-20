package us.kbase.auth2.lib.exceptions;

/** Thrown when a required parameter was not provided.
 * @author gaprice@lbl.gov
 *
 */
@SuppressWarnings("serial")
public class MissingParameterException extends AuthException {

	public MissingParameterException(final String message) {
		super(ErrorType.MISSING_PARAMETER, message);
	}
}
