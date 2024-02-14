package us.kbase.auth2.lib.storage.exceptions;

/** 
 * Thrown when an exception occurs regarding the authorization storage system
 * @author gaprice@lbl.gov
 *
 */
public class AuthStorageException extends Exception {

	private static final long serialVersionUID = 1L;
	
	public AuthStorageException(String message) { super(message); }
	public AuthStorageException(String message, Throwable cause) {
		super(message, cause);
	}
}
