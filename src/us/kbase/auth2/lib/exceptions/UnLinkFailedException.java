package us.kbase.auth2.lib.exceptions;

/** Unlinking an account failed.
 * @author gaprice@lbl.gov
 *
 */
@SuppressWarnings("serial")
public class UnLinkFailedException extends AuthException {

	public UnLinkFailedException(String message) {
		super(ErrorType.UNLINK_FAILED, message);
	}

	public UnLinkFailedException(String message, Throwable cause) {
		super(ErrorType.UNLINK_FAILED, message, cause);
	}
}
