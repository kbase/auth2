package us.kbase.auth2.lib;

import static us.kbase.auth2.lib.Utils.checkString;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import us.kbase.auth2.lib.exceptions.ErrorType;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;

public class UserName {

	//TODO TEST
	//TODO JAVADOC
	
	// this must never be a valid username 
	private final static String ROOT_NAME = "***ROOT***";
	public final static UserName ROOT;
	static {
		try {
			ROOT = new UserName(ROOT_NAME);
		} catch (IllegalParameterException | MissingParameterException e) {
			throw new RuntimeException("Programming error: " +
					e.getMessage(), e);
		}
	}
	private final static Pattern INVALID_USER_NAME =
			Pattern.compile("[^a-z\\d_]");
	private final static int MAX_NAME_LENGTH = 100;
	
	private final String name;

	public UserName(final String name)
			throws MissingParameterException, IllegalParameterException {
		checkString(name, "user name", MAX_NAME_LENGTH);
		if (name.trim().equals(ROOT_NAME)) {
			this.name = ROOT_NAME;
		} else {
			final Matcher m = INVALID_USER_NAME.matcher(name);
			if (m.find()) {
				throw new IllegalParameterException(ErrorType.ILLEGAL_USER_NAME, String.format(
						"Illegal character in user name %s: %s", name, m.group()));
			}
			this.name = name.trim();
		}
	}
	
	public boolean isRoot() {
		return name.equals(ROOT_NAME);
	}

	public String getName() {
		return name;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((name == null) ? 0 : name.hashCode());
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
		UserName other = (UserName) obj;
		if (name == null) {
			if (other.name != null) {
				return false;
			}
		} else if (!name.equals(other.name)) {
			return false;
		}
		return true;
	}
	
}
