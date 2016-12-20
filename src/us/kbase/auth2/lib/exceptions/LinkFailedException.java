package us.kbase.auth2.lib.exceptions;

/** Thrown when linking accounts failed.
 * @author gaprice@lbl.gov
 *
 */
@SuppressWarnings("serial")
public class LinkFailedException extends AuthException {

	public LinkFailedException(final String message) {
		super(ErrorType.LINK_FAILED, message);
	}
}
