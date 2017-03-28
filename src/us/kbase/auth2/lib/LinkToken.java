package us.kbase.auth2.lib;

import static us.kbase.auth2.lib.Utils.nonNull;

import com.google.common.base.Optional;

import us.kbase.auth2.lib.token.TemporaryToken;

/** Provides a token for continuing the account linking process if needed.
 * 
 * If the linking process is concluded and the account linked, then isLinked() will be true and
 * the token will be absent.
 * 
 * If there are still more steps to be completed in the linking process, isLinked() will be false
 * and a temporary token supplied which can be used to continue the linking process.
 * @author gaprice@lbl.gov
 *
 */
public class LinkToken {
	
	private final Optional<TemporaryToken> token;
	private final Optional<LinkIdentities> idents;
	
	/** Create a LinkToken for the case where the linking process is concluded and no further
	 * actions are required.
	 */
	public LinkToken() {
		this.token = Optional.absent();
		this.idents = Optional.absent();
	}
	
	/** Create a LinkToken for the case where more actions are required, and thus a token is
	 * provided to allow continuing with the linking process.
	 * @param token a temporary token associated with the state of the linking process in the auth
	 * storage system.
	 * @param linkIdentities the identities available for linking.
	 */
	public LinkToken(final TemporaryToken token, final LinkIdentities linkIdentities) {
		nonNull(token, "token");
		nonNull(linkIdentities, "linkIdentities");
		this.idents = Optional.of(linkIdentities);
		this.token = Optional.of(token);
	}

	/** True if the linking process is completed and no further actions are necessary.
	 * @return true if the linking process is complete.
	 */
	public boolean isLinked() {
		return !token.isPresent();
	}

	/** Get a temporary token to use to complete the linking process.
	 * @return a temporary token, or absent if the linking process is complete.
	 */
	public Optional<TemporaryToken> getTemporaryToken() {
		return token;
	}
	
	/** Get the identities available for linking.
	 * @return the identities available for linking, or absent if linking process is complete.
	 */
	public Optional<LinkIdentities> getLinkIdentities() {
		return idents;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((idents == null) ? 0 : idents.hashCode());
		result = prime * result + ((token == null) ? 0 : token.hashCode());
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
		LinkToken other = (LinkToken) obj;
		if (idents == null) {
			if (other.idents != null) {
				return false;
			}
		} else if (!idents.equals(other.idents)) {
			return false;
		}
		if (token == null) {
			if (other.token != null) {
				return false;
			}
		} else if (!token.equals(other.token)) {
			return false;
		}
		return true;
	}
}
