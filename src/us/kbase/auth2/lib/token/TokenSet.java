package us.kbase.auth2.lib.token;

import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

/** A set of tokens, including one current token for a user.
 * @author gaprice@lbl.gov
 *
 */
public class TokenSet {

	private final HashedToken currentToken;
	private final Set<HashedToken> tokens;
	
	/** Create a new token set.
	 * @param current the current token for the user associated with this token set.
	 * @param tokens other tokens. If the current token matches on of the tokens in this set,
	 * the token is removed from the set.
	 */
	public TokenSet(
			final HashedToken current,
			final Set<HashedToken> tokens) {
		if (current == null) {
			throw new NullPointerException("current");
		}
		this.currentToken = current;
		if (tokens == null) {
			throw new NullPointerException("tokens");
		}
		final Set<HashedToken> nt = new HashSet<>(tokens);
		final Iterator<HashedToken> i = nt.iterator();
		while (i.hasNext()) {
			final HashedToken ht = i.next();
			if (ht == null) {
				throw new NullPointerException("One of the tokens in the incoming set is null");
			}
			if (!ht.getUserName().equals(current.getUserName())) {
				throw new IllegalArgumentException(
						"Mixing tokens from different users is not allowed");
			}
			if (ht.getId().equals(current.getId())) {
				i.remove();
			}
		}
		this.tokens = Collections.unmodifiableSet(nt);
	}

	/** Get the current token.
	 * @return the current token.
	 */
	public HashedToken getCurrentToken() {
		return currentToken;
	}

	/** Get all tokens other than the current token.
	 * @return all other tokens.
	 */
	public Set<HashedToken> getTokens() {
		return tokens;
	}
}
