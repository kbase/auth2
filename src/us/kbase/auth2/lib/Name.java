package us.kbase.auth2.lib;

import static java.util.Objects.requireNonNull;
import static us.kbase.auth2.lib.Utils.checkString;
import static us.kbase.auth2.lib.Utils.checkStringNoCheckedException;

import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;

/** The base class for objects that are names.
 * @author gaprice@lbl.gov
 *
 */
public class Name implements Comparable<Name> {
	
	private final String name;
	
	/** Create a new name.
	 * 
	 * Prior to any operations .trim() is called on the name.
	 * 
	 * @param name the name to create.
	 * @param type the type of the name. This string is included in exceptions but is otherwise
	 * unused.
	 * @param maxCodePoints the maximum number of code points in the name. Values less than 1
	 * are ignored.
	 * @throws MissingParameterException if the name is null or the empty string.
	 * @throws IllegalParameterException if the name is too long or if the name contains
	 * control characters.
	 */
	public Name(final String name, final String type, final int maxCodePoints)
			throws MissingParameterException, IllegalParameterException {
		this.name = checkValidName(name, type, maxCodePoints);
	}
	
	/** Check that a name is valid.
	 * 
	 * Prior to any operations .trim() is called on the name.
	 * 
	 * @param name the name.
	 * @param type the type of the name. This string is included in exceptions but is otherwise
	 * unused.
	 * @param maxCodePoints the maximum number of code points in the name. Values less than 1
	 * are ignored.
	 * @return the trimmed name.
	 * @throws MissingParameterException if the name is null or the empty string.
	 * @throws IllegalParameterException if the name is too long or if the name contains
	 * control characters.
	 */
	public static String checkValidName(
			String name,
			final String type,
			final int maxCodePoints)
			throws MissingParameterException, IllegalParameterException {
		checkStringNoCheckedException(type, "type");
		checkString(name, type, maxCodePoints);
		name = name.trim();
		final boolean[] containsControlChars = {false};
		name.codePoints().forEach(i -> {
			containsControlChars[0] = containsControlChars[0] || Character.isISOControl(i);
		});
		if (containsControlChars[0]) {
			throw new IllegalParameterException(type + " contains control characters");
		}
		return name;
	}
	
	/** Get the name.
	 * @return the name.
	 */
	public String getName() {
		return name;
	}

	@Override
	public int compareTo(final Name userName) {
		requireNonNull(userName, "name");
		return getName().compareTo(userName.getName());
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
		Name other = (Name) obj;
		if (name == null) {
			if (other.name != null) {
				return false;
			}
		} else if (!name.equals(other.name)) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append(getClass().getSimpleName() + " [name=");
		builder.append(name);
		builder.append("]");
		return builder.toString();
	}
}
