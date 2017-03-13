package us.kbase.auth2.lib;

import static us.kbase.auth2.lib.Utils.nonNull;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.google.common.base.Optional;

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
public class UserName extends Name{

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
	public final static int MAX_NAME_LENGTH = 100;
	
	/** Create a new user name.
	 * @param name the user name.
	 * @throws MissingParameterException if the name supplied is null or empty.
	 * @throws IllegalParameterException if the name supplied has illegal characters or is too
	 * long.
	 */
	public UserName(final String name)
			throws MissingParameterException, IllegalParameterException {
		super(name, "user name", MAX_NAME_LENGTH);
		if (!name.trim().equals(ROOT_NAME)) {
			final Matcher m = INVALID_CHARS.matcher(name);
			if (m.find()) {
				throw new IllegalParameterException(ErrorType.ILLEGAL_USER_NAME, String.format(
						"Illegal character in user name %s: %s", name, m.group()));
			}
			if (!Character.isLetter(name.codePointAt(0))) {
				throw new IllegalParameterException(ErrorType.ILLEGAL_USER_NAME,
						"Username must start with a letter");
			}
		}
	}
	
	/** Returns whether this user name represents the root user.
	 * @return true if this user name represents the root user.
	 */
	public boolean isRoot() {
		return getName().equals(ROOT_NAME);
	}

	// returns the null if the name contains no lowercase letters.
	/** Given a string, returns a new name based on that string that is a legal user name. If
	 * it is not possible construct a valid user name, absent is returned.
	 * @param suggestedUserName the user name to mutate into a legal user name.
	 * @return the new user name, or absent if mutation proved impossible.
	 */
	public static Optional<UserName> sanitizeName(final String suggestedUserName) {
		nonNull(suggestedUserName, "suggestedUserName");
		final String s = suggestedUserName.toLowerCase().replaceAll(INVALID_CHARS_REGEX, "")
				.replaceAll("^[^a-z]+", "");
		try {
			return s.isEmpty() ? Optional.absent() : Optional.of(new UserName(s));
		} catch (IllegalParameterException | MissingParameterException e) {
			throw new RuntimeException("This should be impossible", e);
		}
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("UserName [getName()=");
		builder.append(getName());
		builder.append("]");
		return builder.toString();
	}
}
