package us.kbase.auth2.lib.token;

import us.kbase.auth2.lib.Name;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;

/** Represents a user-assigned name for a token. The name is an arbitrary string of no more than
 * 100 characters.
 * @author gaprice@lbl.gov
 *
 */
public class TokenName extends Name {
	
	/** Create a token name.
	 * @param name the name.
	 * @throws MissingParameterException if the name is null or the empty string.
	 * @throws IllegalParameterException if the name is longer than 100 characters or contains
	 * control characters.
	 */
	public TokenName(final String name)
			throws MissingParameterException, IllegalParameterException {
		super(name, "token name", 100);
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("TokenName [getName()=");
		builder.append(getName());
		builder.append("]");
		return builder.toString();
	}
}
