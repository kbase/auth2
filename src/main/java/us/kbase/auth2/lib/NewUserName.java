package us.kbase.auth2.lib;

import static java.util.Objects.requireNonNull;

import java.util.Optional;
import java.util.regex.Pattern;

import us.kbase.auth2.lib.exceptions.ErrorType;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;

/** A user name for a new user.
 * 
 * Valid user names are strings of up to 100 characters consisting of lowercase ASCII letters,
 * digits, and the underscore. The first character must be a letter.
 * 
 * Unlike existing users, new users may also not have more than 1 underscore in a row and may not
 * have trailing underscores.
 * 
 * The only exception is the user name ***ROOT***, which represents the root user.
 *
 */
public class NewUserName extends UserName {
	
	/** The username for the root user. */
	public final static NewUserName ROOT;
	static {
		try {
			ROOT = new NewUserName(ROOT_NAME);
		} catch (IllegalParameterException | MissingParameterException e) {
			throw new RuntimeException("Programming error: " + e.getMessage(), e);
		}
	}
	
	private final static Pattern REPEATING_UNDERSCORES = Pattern.compile("_+");
	// just need to match one since the repeating underscores will have removed any more
	private final static Pattern TRAILING_UNDERSCORE = Pattern.compile("_$");

	/** Create a user name for a new, to be created, user.
	 * @param name the user name.
	 * @throws MissingParameterException if the name supplied is null or empty.
	 * @throws IllegalParameterException if the name supplied has illegal characters or is too
	 * long.
	 */
	public NewUserName(final String name)
			throws MissingParameterException, IllegalParameterException {
		super(name);
		if (name.contains("__") || name.endsWith("_")) {
			throw new IllegalParameterException(ErrorType.ILLEGAL_USER_NAME,
					"New usernames cannot contain repeating underscores or "
					+ "trailing underscores"
			);
		}
	}
	
	/** Given a string, returns a new name based on that string that is a legal user name. If
	 * it is not possible construct a valid user name, empty() is returned.
	 * @param suggestedUserName the user name to mutate into a legal user name.
	 * @return the new user name, or empty() if mutation proved impossible.
	 */
	public static Optional<UserName> sanitizeName(final String suggestedUserName) {
		requireNonNull(suggestedUserName, "suggestedUserName");
		String cleaned = suggestedUserName.toLowerCase();
		cleaned = INVALID_CHARS.matcher(cleaned).replaceAll("");
		cleaned = FORCE_ALPHA_FIRST_CHAR.matcher(cleaned).replaceAll("");
		cleaned = REPEATING_UNDERSCORES.matcher(cleaned).replaceAll("_");
		cleaned = TRAILING_UNDERSCORE.matcher(cleaned).replaceAll("");
		try {
			return cleaned.isEmpty() ? Optional.empty() : Optional.of(new UserName(cleaned));
		} catch (IllegalParameterException | MissingParameterException e) {
			throw new RuntimeException("This should be impossible", e);
		}
	}
	
	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("NewUserName [getName()=");
		builder.append(getName());
		builder.append("]");
		return builder.toString();
	}
}
