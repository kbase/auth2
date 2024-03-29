package us.kbase.auth2.lib.token;

import static java.util.Objects.requireNonNull;

import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.TreeSet;

/** A set of tokens, including one current token for a user.
 * @author gaprice@lbl.gov
 *
 */
public class TokenSet {
	
	private static class TokenComparator implements Comparator<StoredToken> {

		@Override
		public int compare(final StoredToken t1, final StoredToken t2) {
			return t1.getId().toString().compareTo(t2.getId().toString());
		}
		
	}

	private final StoredToken currentToken;
	private final Set<StoredToken> tokens;
	
	/** Create a new token set.
	 * @param current the current token for the user associated with this token set.
	 * @param tokens other tokens. If the current token matches one of the tokens in this set,
	 * the token is removed from the set.
	 */
	public TokenSet(
			final StoredToken current,
			final Set<StoredToken> tokens) {
		requireNonNull(current, "current");
		requireNonNull(tokens, "tokens");
		this.currentToken = current;
		// in case incoming set is unmodifiable
		final Set<StoredToken> putative = new HashSet<>(tokens);
		final Iterator<StoredToken> i = putative.iterator();
		while (i.hasNext()) {
			final StoredToken ht = i.next();
			requireNonNull(ht, "One of the tokens in the incoming set is null");
			if (!ht.getUserName().equals(current.getUserName())) {
				throw new IllegalArgumentException(
						"Mixing tokens from different users is not allowed");
			}
			if (ht.getId().equals(current.getId())) {
				i.remove();
			}
		}
		final Set<StoredToken> nt = new TreeSet<>(new TokenComparator());
		nt.addAll(putative);
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
