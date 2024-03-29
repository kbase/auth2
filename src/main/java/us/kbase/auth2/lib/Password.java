package us.kbase.auth2.lib;


import com.nulabinc.zxcvbn.Zxcvbn;
import com.nulabinc.zxcvbn.Strength;

import us.kbase.auth2.lib.exceptions.IllegalPasswordException;

import static java.util.Objects.requireNonNull;

import java.util.Arrays;

/** A password.
 * 
 * This class wraps a character array containing a password.
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
	 *   3 # safely unguessable: moderate protection from offline slow-hash scenario.
	 *       (guesses < 10^10)
	 *   4 # very unguessable: strong protection from offline slow-hash scenario.
	 *       (guesses >= 10^10)
	 */
	private static final int MIN_PASSWORD_STRENGTH_SCORE = 3;
	
	private static final int MAX_PASSWORD_LENGTH = 256;
	
	private final char[] password;
	
	/**
	 * Writes the 0 character to every position of the password array to clear from memory.
	 * @param password the password to clear.
	 */
	public static void clearPasswordArray(final char[] password) {
		if (password != null) {
			for (int i = 0; i < password.length; i++) {
				password[i] = '0';
			}
		}
	}
	
	/** Create a password.  Any further changes to the input char array will not be
	 * reflected.  You should use {@link #clearPasswordArray(char[])} to clear your input
	 * array as soon as the Password object is initialized to prevent your password
	 * from lingering in memory.
	 * @param password the password to wrap.
	 */
	public Password(final char[] password) {
		requireNonNull(password, "password");
		this.password = Arrays.copyOf(password, password.length);
	}
	
	/** Get the password. This makes a copy of the password array, and should be cleared with
	 * {@link #clearPasswordArray(char[])} as soon as the password is no longer needed.
	 * @return the password.
	 */
	public char[] getPassword() {
		return Arrays.copyOf(password, password.length);
	}
	
	/** Writes the 0 character to every position in the password array. */
	public void clear() {
		clearPasswordArray(password);
	}
	
	/** Check for password validity (length and strength requirements)
	 * @throws IllegalPasswordException if the password is not valid
	 */
	public void checkValidity() throws IllegalPasswordException {
		// check length requirements
		if (Character.codePointCount(password, 0, password.length) > MAX_PASSWORD_LENGTH) {
			throw new IllegalPasswordException("Password exceeds max length ("+
												MAX_PASSWORD_LENGTH + ")");
		}
		
		// check strength requirement
		final Strength strength = new Zxcvbn().measure(new String(password));
		if (strength.getScore() < MIN_PASSWORD_STRENGTH_SCORE) {
			final String warning = strength.getFeedback().getWarning();
			throw new IllegalPasswordException("Password is not strong enough. " + warning);
		}
	}
	
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + Arrays.hashCode(password);
		return result;
	}
	
	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		final Password other = (Password) obj;
		return Arrays.equals(password, other.password);
	}
}
