package us.kbase.auth2.lib.exceptions;

/** Thrown when an error occurs attempting to retrieve the a user's identity from a 3rd
 * party.
 * @author gaprice@lbl.gov 
 */
@SuppressWarnings("serial")
public class IdentityRetrievalException extends AuthenticationException {
	
	public IdentityRetrievalException(final String message) {
		super(ErrorType.ID_RETRIEVAL_FAILED, message);
	}
}
