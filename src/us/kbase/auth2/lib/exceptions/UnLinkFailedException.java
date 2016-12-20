package us.kbase.auth2.lib.exceptions;

/** Thrown when unlinking an account failed.
 * @author gaprice@lbl.gov
 *
 */
@SuppressWarnings("serial")
public class UnLinkFailedException extends AuthException {

	public UnLinkFailedException(final String message) {
		super(ErrorType.UNLINK_FAILED, message);
	}
}
