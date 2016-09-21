package us.kbase.auth2.lib.exceptions;

/** Linking accounts failed.
 * @author gaprice@lbl.gov
 *
 */
@SuppressWarnings("serial")
public class LinkFailedException extends AuthException {

	public LinkFailedException(String message) {
		super(ErrorType.LINK_FAILED, message);
	}

	public LinkFailedException(String message, Throwable cause) {
		super(ErrorType.LINK_FAILED, message, cause);
	}
}
