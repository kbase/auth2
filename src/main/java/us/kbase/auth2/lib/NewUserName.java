package us.kbase.auth2.lib;

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
	
	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("NewUserName [getName()=");
		builder.append(getName());
		builder.append("]");
		return builder.toString();
	}
}
