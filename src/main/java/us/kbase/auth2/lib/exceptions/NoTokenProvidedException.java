package us.kbase.auth2.lib.exceptions;

/** Thrown when a token was expected but not provided.
 * @author gaprice@lbl.gov
 */
@SuppressWarnings("serial")
public class NoTokenProvidedException extends AuthException {

	public NoTokenProvidedException(final String message) {
		super(ErrorType.NO_TOKEN, message);
	}
}
