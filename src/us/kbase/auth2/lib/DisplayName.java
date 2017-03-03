package us.kbase.auth2.lib;

import static us.kbase.auth2.lib.Utils.checkString;

import java.util.Arrays;
import java.util.List;

import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;

/** A display name for a user. Unlike a user name, a display name may not be unique and has very
 * few restrictions regarding the content of the name other than a maximum length of 100.
 * @author gaprice@lbl.gov
 *
 */
public class DisplayName {

	private final static int MAX_NAME_LENGTH = 100;
	
	/* What's ok for a display name? for now just a non-empty string < 100 chars, trimmed. */
	
	private final String name;
	
	/** Create a display name.
	 * @param name the name.
	 * @throws MissingParameterException if the name is null or the empty string.
	 * @throws IllegalParameterException if the name is too long.
	 */
	public DisplayName(final String name)
			throws MissingParameterException, IllegalParameterException {
		checkString(name, "display name", MAX_NAME_LENGTH);
		this.name = name.trim().replaceAll("\\p{Cntrl}", "");;
	}
	
	/** Get the display name.
	 * @return the display name.
	 */
	public String getName() {
		return name;
	}
	
	/** Get the canonical display name for this name. Returns a list of the whitespace separated
	 * tokens in the display name. The tokens are lowercased.
	 * @return the canonical display name.
	 */
	public List<String> getCanonicalDisplayName() {
		//TODO SEARCH remove punctuation on the outside of tokens, needs to handle unicode
		return Arrays.asList(name.toLowerCase().split("\\s+"));
	}
	
	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("DisplayName [name=");
		builder.append(name);
		builder.append("]");
		return builder.toString();
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
		DisplayName other = (DisplayName) obj;
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
