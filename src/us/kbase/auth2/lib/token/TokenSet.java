package us.kbase.auth2.lib.token;

import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;


public class TokenSet {

	private final HashedToken currentToken;
	private final Set<HashedToken> tokens;
	
	public TokenSet(
			final HashedToken current,
			final Set<HashedToken> tokens) {
		if (current == null) {
			throw new NullPointerException("current");
		}
		final Set<HashedToken> nt = new HashSet<>(tokens);
		final Iterator<HashedToken> i = nt.iterator();
		while (i.hasNext()) {
			if (i.next().getId().equals(current.getId())) {
				i.remove();
			}
		}
		this.currentToken = current;
		this.tokens = Collections.unmodifiableSet(nt);
	}

	public HashedToken getCurrentToken() {
		return currentToken;
	}

	public Set<HashedToken> getTokens() {
		return tokens;
	}
}
