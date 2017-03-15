package us.kbase.auth2.lib;

import java.util.Arrays;
import java.util.List;

import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;

/** A display name for a user. Unlike a user name, a display name may not be unique and has very
 * few restrictions regarding the content of the name other than a maximum length of 100.
 * @author gaprice@lbl.gov
 *
 */
public class DisplayName extends Name {

	private final static int MAX_NAME_LENGTH = 100;
	
	/* What's ok for a display name? for now just a non-empty string < 100 chars, trimmed. */
	
	/** Create a display name.
	 * @param name the name.
	 * @throws MissingParameterException if the name is null or the empty string.
	 * @throws IllegalParameterException if the name is too long or contains control characters.
	 */
	public DisplayName(final String name)
			throws MissingParameterException, IllegalParameterException {
		super(name, "display name", MAX_NAME_LENGTH);
	}
	
	/** Get the canonical display name for this name. Returns a list of the whitespace separated
	 * tokens in the display name. The tokens are lowercased.
	 * @return the canonical display name.
	 */
	public List<String> getCanonicalDisplayName() {
		//TODO SEARCH remove punctuation on the outside of tokens, needs to handle unicode
		return Arrays.asList(getName().toLowerCase().split("\\s+"));
	}
	
	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("DisplayName [getName()=");
		builder.append(getName());
		builder.append("]");
		return builder.toString();
	}
}
