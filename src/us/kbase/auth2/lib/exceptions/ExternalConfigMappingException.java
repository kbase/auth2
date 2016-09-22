package us.kbase.auth2.lib.exceptions;

@SuppressWarnings("serial")
public class ExternalConfigMappingException extends Exception {

	public ExternalConfigMappingException(final String message) {
		super(message);
	}

	public ExternalConfigMappingException(
			final String message,
			final Throwable cause) {
		super(message, cause);
	}
}
