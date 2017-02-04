package us.kbase.auth2.lib;

/** A password.
 * 
 * This class wraps a character array containing a password. Note that it wraps the passed-in
 * array as-is and does not make a copy. Hence, if Password.clear() is called, the passed-in array
 * is zeroed out. If the array is changed outside the class, the state of the class will change as
 * well.
 * 
 * @author gaprice@lbl.gov
 *
 */
public class Password {

	//TODO TEST
	
	private final char[] password;
	
	/** Create a password. Note that the incoming array is not copied, and any changes to the array
	 * will be reflected in this class.
	 * @param password the password to wrap.
	 */
	public Password(final char[] password) {
		//TODO PWD appropriate checking that the password is strong
		//TODO PWD max length
		// https://github.com/nulab/zxcvbn4j
		// may need to have a non-checking constructor, only need to check on creation
		if (password == null) {
			throw new NullPointerException("password");
		}
		this.password = password;
	}
	
	/** Get the password.
	 * @return the password.
	 */
	public char[] getPassword() {
		return password;
	}
	
	/** Writes the 0 character to every position in the password array. */
	public void clear() {
		for (int i = 0; i < password.length; i++) {
			password[i] = '0';
		}
	}
}
