package us.kbase.auth2.lib;

import static us.kbase.auth2.lib.Utils.checkString;

import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;

public class DisplayName {

	//TODO TEST
	//TODO JAVADOC
	
	private final static int MAX_NAME_LENGTH = 100;
	
	/* What's ok for a display name? for now just a non-empty string < 100 chars, trimmed. */
	
	private final String name;
	
	public DisplayName(final String name)
			throws MissingParameterException, IllegalParameterException {
		checkString(name, "display name", MAX_NAME_LENGTH);
		this.name = name.trim();
	}
	
	public String getName() {
		return name;
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
