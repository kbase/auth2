package us.kbase.auth2.lib.exceptions;

/** Thrown when a test mode method is called but test mode is not enabled.
 * @author gaprice@lbl.gov
 *
 */
@SuppressWarnings("serial")
public class TestModeException extends AuthException {

	public TestModeException(final ErrorType type, final String message) {
		super(type, message);
	}
}
