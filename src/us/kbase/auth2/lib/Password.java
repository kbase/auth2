package us.kbase.auth2.lib;

import com.nulabinc.zxcvbn.Zxcvbn;

import us.kbase.auth2.lib.exceptions.IllegalPasswordException;

import com.nulabinc.zxcvbn.Strength;

/** A password.
 * 
 * This class wraps a character array containing a password. Note that it wraps the passed-in
 * array as-is and does not make a copy. Hence, if Password.clear() is called, the passed-in array
 * is zeroed out. If the array is changed outside the class, the state of the class will change as
 * well.
 * 
 * @author gaprice@lbl.gov
 * @author mwsneddon@lbl.gov
 *
 */
public class Password {

	/** Sets the minimum strength score required of a password.  The zxcvbn strength score is:
	 * 
	 * (from https://github.com/dropbox/zxcvbn, https://github.com/nulab/zxcvbn4j)
	 *   Integer from 0-4 (useful for implementing a strength bar)
	 *   0 # too guessable: risky password. (guesses < 10^3)
	 *   1 # very guessable: protection from throttled online attacks. (guesses < 10^6)
	 *   2 # somewhat guessable: protection from unthrottled online attacks. (guesses < 10^8)
	 *   3 # safely unguessable: moderate protection from offline slow-hash scenario. (guesses < 10^10)
	 *   4 # very unguessable: strong protection from offline slow-hash scenario. (guesses >= 10^10)
	 */
	private static final int MIN_PASSWORD_STRENGTH_SCORE = 3;
	
	private static final int MAX_PASSWORD_LENGTH = 256;
	
	private final char[] password;
	
	/** Create a password. Note that the incoming array is not copied, and any changes to the array
	 * will be reflected in this class.
	 * @param password the password to wrap.
	 */
	public Password(final char[] password) {
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
	
	/** Check for password validity (length and strength requirements)
	 * @throws IllegalPasswordException if the password is not valid
	 */
	public void checkValidity() throws IllegalPasswordException {
		// check length requirements
		if(password.length > MAX_PASSWORD_LENGTH) {
			throw new IllegalPasswordException("Password exceeds max length ("+
												MAX_PASSWORD_LENGTH+")");
		}
		
		// check strength requirement
		Strength strength = new Zxcvbn().measure(new String(password));
		if(strength.getScore() < MIN_PASSWORD_STRENGTH_SCORE) {
			String warning = strength.getFeedback().getWarning();
			throw new IllegalPasswordException("Password is not strong enough. " + warning);
		}
	}
}
