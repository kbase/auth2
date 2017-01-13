package us.kbase.auth2.lib.storage.exceptions;

/** 
 * Thrown when an exception occurs regarding initialization of the authorization storage system
 * @author gaprice@lbl.gov
 *
 */
public class StorageInitException extends AuthStorageException {

	private static final long serialVersionUID = 1L;
	
	public StorageInitException(String message) { super(message); }
	public StorageInitException(String message, Throwable cause) {
		super(message, cause);
	}
}
