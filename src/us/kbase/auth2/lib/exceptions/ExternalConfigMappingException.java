package us.kbase.auth2.lib.exceptions;

/** Exception thrown when mapping an external configuration element from one form to another fails.
 * @author gaprice@lbl.gov
 *
 */
@SuppressWarnings("serial")
public class ExternalConfigMappingException extends Exception {

	public ExternalConfigMappingException(final String message) {
		super(message);
	}

	public ExternalConfigMappingException(final String message, final Throwable cause) {
		super(message, cause);
	}
}
