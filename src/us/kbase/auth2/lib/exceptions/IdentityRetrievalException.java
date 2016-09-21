package us.kbase.auth2.lib.exceptions;

/** An error occurred attempting to retrieve the a user's identity from a 3rd
 * party.
 * @author gaprice@lbl.gov 
 */
@SuppressWarnings("serial")
public class IdentityRetrievalException extends AuthenticationException {
	
	public IdentityRetrievalException(final String message) {
		super(ErrorType.ID_RETRIEVAL_FAILED, message);
	}
	
	public IdentityRetrievalException(
			final String message,
			final Throwable cause) {
		super(ErrorType.ID_RETRIEVAL_FAILED, message, cause);
	}
}
