package us.kbase.auth2.lib.exceptions;

/** Thrown when an environment does not exist.
 * @author gaprice@lbl.gov
 *
 */
@SuppressWarnings("serial")
public class NoSuchEnvironmentException extends AuthException {

	public NoSuchEnvironmentException(final String message) {
		super(ErrorType.NO_SUCH_ENVIRONMENT, message);
	}
}
