package us.kbase.auth2.lib.exceptions;

/** Base class of all authorization service exceptions.
 * @author gaprice@lbl.gov 
 */
@SuppressWarnings("serial")
public class AuthException extends Exception {
	
	private final ErrorType err;
	
	public AuthException(final ErrorType err, final String message) {
		super(getMsg(err, message));
		this.err = err;
	}

	private static String getMsg(final ErrorType err, final String message) {
		if (err == null) {
			throw new NullPointerException("err");
		}
		return err.getErrorCode() + " " + err.getError() + 
				(message == null || message.isEmpty() ? "" : ": " + message);
	}
	
	public AuthException(
			final ErrorType err,
			final String message,
			final Throwable cause) {
		super(getMsg(err, message), cause);
		this.err = err;
	}

	public ErrorType getErr() {
		return err;
	}
}
