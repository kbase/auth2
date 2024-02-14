package us.kbase.auth2.lib;

import static us.kbase.auth2.lib.Utils.checkStringNoCheckedException;

import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

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
	
	/** Get the canonical display name for a string. Returns a list of the whitespace and hyphen
	 * separated tokens in the name. The tokens are lowercased, punctuation in the token is
	 * removed, and non-unique elements are removed.
	 * @param name the string to analyze.
	 * @return the canonical display name.
	 */
	public static List<String> getCanonicalDisplayName(final String name) {
		checkStringNoCheckedException(name, "name");
		final String[] tokens = name.toLowerCase().split("[-\\s]");
		final Set<String> ret = new LinkedHashSet<>();
		for (final String t: tokens) {
			final StringBuilder sb = new StringBuilder();
			t.codePoints().filter(cp -> Character.isLetterOrDigit(cp))
					.forEach(cp -> sb.appendCodePoint(cp));
			if (sb.length() > 0) {
				ret.add(sb.toString());
			}
		}
		return new LinkedList<>(ret);
	}
	
	/** Get the canonical display name for this name. Returns a list of the whitespace and hyphen
	 * separated tokens in the display name. The tokens are lowercased, punctuation in the token
	 * is removed, and non-unique elements are removed.
	 * @return the canonical display name.
	 */
	public List<String> getCanonicalDisplayName() {
		return getCanonicalDisplayName(getName());
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
