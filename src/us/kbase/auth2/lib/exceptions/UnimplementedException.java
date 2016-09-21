package us.kbase.auth2.lib.exceptions;

@SuppressWarnings("serial")
public class UnimplementedException extends RuntimeException {

	public UnimplementedException() {
		super();
	}

	public UnimplementedException(String message) {
		super(message);
	}

	public UnimplementedException(Throwable cause) {
		super(cause);
	}

	public UnimplementedException(String message, Throwable cause) {
		super(message, cause);
	}
}
