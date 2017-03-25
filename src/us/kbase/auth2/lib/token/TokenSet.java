package us.kbase.auth2.lib.token;

import static us.kbase.auth2.lib.Utils.nonNull;

import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

/** A set of tokens, including one current token for a user.
 * @author gaprice@lbl.gov
 *
 */
public class TokenSet {

	private final StoredToken currentToken;
	private final Set<StoredToken> tokens;
	
	/** Create a new token set.
	 * @param current the current token for the user associated with this token set.
	 * @param tokens other tokens. If the current token matches on of the tokens in this set,
	 * the token is removed from the set.
	 */
	public TokenSet(
			final StoredToken current,
			final Set<StoredToken> tokens) {
		nonNull(current, "current");
		nonNull(tokens, "tokens");
		this.currentToken = current;
		final Set<StoredToken> nt = new HashSet<>(tokens);
		final Iterator<StoredToken> i = nt.iterator();
		while (i.hasNext()) {
			final StoredToken ht = i.next();
			nonNull(ht, "One of the tokens in the incoming set is null");
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
	public StoredToken getCurrentToken() {
		return currentToken;
	}

	/** Get all tokens other than the current token.
	 * @return all other tokens.
	 */
	public Set<StoredToken> getTokens() {
		return tokens;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((currentToken == null) ? 0 : currentToken.hashCode());
		result = prime * result + ((tokens == null) ? 0 : tokens.hashCode());
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
		TokenSet other = (TokenSet) obj;
		if (currentToken == null) {
			if (other.currentToken != null) {
				return false;
			}
		} else if (!currentToken.equals(other.currentToken)) {
			return false;
		}
		if (tokens == null) {
			if (other.tokens != null) {
				return false;
			}
		} else if (!tokens.equals(other.tokens)) {
			return false;
		}
		return true;
	}
	
	
}
