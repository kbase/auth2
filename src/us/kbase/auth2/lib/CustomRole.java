package us.kbase.auth2.lib;

import static us.kbase.auth2.lib.Utils.checkString;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;

/** An admin defined role that can be assigned to a user.
 * 
 * A role consists of an ID that is a {@literal < 100} character string consisting of ASCII
 * letters, digits, and the underscore, and a description that is a {@literal < 1000} character
 * string.
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
		checkValidRoleID(id);
		checkString(desc, "custom role description", MAX_DESC_LENGTH);
		this.id = id;
		this.desc = desc.trim();
	}
	
	public static void checkValidRoleID(final String id)
			throws MissingParameterException, IllegalParameterException {
		Name.checkValidName(id, "custom role id", MAX_ROLE_LENGTH);
		final Matcher m = INVALID_CHARS.matcher(id);
		if (m.find()) {
			throw new IllegalParameterException(String.format(
					"Illegal character in custom role id %s: %s", id, m.group()));
		}
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
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((desc == null) ? 0 : desc.hashCode());
		result = prime * result + ((id == null) ? 0 : id.hashCode());
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
		CustomRole other = (CustomRole) obj;
		if (desc == null) {
			if (other.desc != null) {
				return false;
			}
		} else if (!desc.equals(other.desc)) {
			return false;
		}
		if (id == null) {
			if (other.id != null) {
				return false;
			}
		} else if (!id.equals(other.id)) {
			return false;
		}
		return true;
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
