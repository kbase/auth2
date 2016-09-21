package us.kbase.auth2.lib.exceptions;

/** Thrown when the requested role does not exist.
 * @author gaprice@lbl.gov
 *
 */
@SuppressWarnings("serial")
public class NoSuchRoleException extends AuthException {

	public NoSuchRoleException(final String message) {
		super(ErrorType.NO_SUCH_ROLE, message);
	}

	public NoSuchRoleException(final String message, final Throwable e) {
		super(ErrorType.NO_SUCH_ROLE, message, e);
	}
	
}
