package us.kbase.auth2.lib;

import static us.kbase.auth2.lib.Utils.checkString;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import us.kbase.auth2.lib.exceptions.ErrorType;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;

/** A user name.
 * 
 * Valid user names are strings of up to 100 characters consisting of lowercase ASCII letters,
 * digits, and the underscore. The first character must be a letter.
 * 
 * The only exception is the user name ***ROOT***, which represents the root user.
 * @author gaprice@lbl.gov
 *
 */
public class UserName {

	// this must never be a valid username 
	private final static String ROOT_NAME = "***ROOT***";
	
	/** The username for the root user. */
	public final static UserName ROOT;
	static {
		try {
			ROOT = new UserName(ROOT_NAME);
		} catch (IllegalParameterException | MissingParameterException e) {
			throw new RuntimeException("Programming error: " +
					e.getMessage(), e);
		}
	}
	
	private static final String INVALID_CHARS_REGEX = "[^a-z\\d_]+";
	private final static Pattern INVALID_CHARS = Pattern.compile(INVALID_CHARS_REGEX);
	private final static int MAX_NAME_LENGTH = 100;
	
	private final String name;

	/** Create a new user name.
	 * @param name the user name.
	 * @throws MissingParameterException if the name supplied is null or empty.
	 * @throws IllegalParameterException if the name supplied has illegal characters or is too
	 * long.
	 */
	public UserName(final String name)
			throws MissingParameterException, IllegalParameterException {
		checkString(name, "user name", MAX_NAME_LENGTH);
		if (name.trim().equals(ROOT_NAME)) {
			this.name = ROOT_NAME;
		} else {
			final Matcher m = INVALID_CHARS.matcher(name);
			if (m.find()) {
				throw new IllegalParameterException(ErrorType.ILLEGAL_USER_NAME, String.format(
						"Illegal character in user name %s: %s", name, m.group()));
			}
			if (!Character.isLetter(name.codePointAt(0))) {
				throw new IllegalParameterException(ErrorType.ILLEGAL_USER_NAME,
						"Username must start with a letter");
			}
			this.name = name;
		}
	}
	
	/** Returns whether this user name represents the root user.
	 * @return true if this user name represents the root user.
	 */
	public boolean isRoot() {
		return name.equals(ROOT_NAME);
	}

	/** Returns the user name as a string.
	 * @return the user name.
	 */
	public String getName() {
		return name;
	}
	
	// returns the null if the name contains no lowercase letters.
	/** Given a string, returns a new name based on that string that is a legal user name. If
	 * it is not possible construct a valid user name, null is returned.
	 * @param suggestedUserName the user name to mutate into a legal user name.
	 * @return the new user name, or null if mutation proved impossible.
	 */
	public static UserName sanitizeName(final String suggestedUserName) {
		final String s = suggestedUserName.toLowerCase().replaceAll(INVALID_CHARS_REGEX, "")
				.replaceAll("^[^a-z]+", "");
		try {
			return s.isEmpty() ? null : new UserName(s);
		} catch (IllegalParameterException | MissingParameterException e) {
			throw new RuntimeException("This should be impossible", e);
		}
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + name.hashCode();
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		final UserName other = (UserName) obj;
		if (!name.equals(other.name)) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("UserName [name=");
		builder.append(name);
		builder.append("]");
		return builder.toString();
	}
	
	
}
