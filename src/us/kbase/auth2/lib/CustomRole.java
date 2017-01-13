package us.kbase.auth2.lib;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static us.kbase.auth2.lib.Utils.checkString;

import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;

/** An admin defined role that can be assigned to a user.
 * 
 * A role consists of an ID that is a < 100 character string consisting of ASCII letters, digits,
 * and the underscore, and a description that is a < 1000 character string.
 * @author gaprice@lbl.gov
 *
 */
public class CustomRole {
	
	private final String id;
	private final String desc;
	
	private final static Pattern INVALID_CHARS = Pattern.compile("[^a-zA-Z\\d_]+");
	private final static int MAX_ROLE_LENGTH = 100;
	private final static int MAX_DESC_LENGTH = 1000;
	
	//TODO ZLATER ROLES remove role from all users function
	
	/** Create a custom role. 
	 * @param id the ID of the role.
	 * @param desc the description of the role.
	 * @throws MissingParameterException if the ID or description is null or empty.
	 * @throws IllegalParameterException if the ID or description is too long or contains
	 * illegal characters.
	 */
	public CustomRole(final String id, final String desc)
			throws MissingParameterException, IllegalParameterException {
		super();
		checkString(id, "custom role id", MAX_ROLE_LENGTH);
		checkString(desc, "custom role description", MAX_DESC_LENGTH);
		final Matcher m = INVALID_CHARS.matcher(id);
		if (m.find()) {
			throw new IllegalParameterException(String.format(
					"Illegal character in custom role id %s: %s", id, m.group()));
		}
		this.id = id;
		this.desc = desc.trim();
	}

	/** Get the role ID.
	 * @return the role ID.
	 */
	public String getID() {
		return id;
	}

	/** Get the role description.
	 * @return the description.
	 */
	public String getDesc() {
		return desc;
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("CustomRole [id=");
		builder.append(id);
		builder.append(", desc=");
		builder.append(desc);
		builder.append("]");
		return builder.toString();
	}
}
