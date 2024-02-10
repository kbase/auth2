package us.kbase.auth2.service.exceptions;

/** Thrown when a configuration is invalid and the service cannot start.
 * @author gaprice@lbl.gov
 *
 */
public class AuthConfigurationException extends Exception {

	private static final long serialVersionUID = 1L;

	public AuthConfigurationException(final String message) {
		super(message);
	}
	
	public AuthConfigurationException(
			final String message,
			final Throwable cause) {
		super(message, cause);
	}
}
