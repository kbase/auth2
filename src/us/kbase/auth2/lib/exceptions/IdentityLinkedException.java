package us.kbase.auth2.lib.exceptions;

/** Thrown when a remote identity is already linked to another user.
 * @author gaprice@lbl.gov
 *
 */
@SuppressWarnings("serial")
public class IdentityLinkedException extends AuthException {

	public IdentityLinkedException(final String message) {
		super(ErrorType.ID_ALREADY_LINKED, message);
	}

}
