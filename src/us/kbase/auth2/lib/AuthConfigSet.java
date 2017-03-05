package us.kbase.auth2.lib;

import static us.kbase.auth2.lib.Utils.nonNull;

/** A configuration set for the authentication instance. Contains the configuration of the
 * authentication instance and a user-definable external configuration that is stored as key-value
 * configuration values in the authentication storage.
 * @author gaprice@lbl.gov
 *
 * @param <T> the external configuration.
 */
public class AuthConfigSet<T extends ExternalConfig> {

	private final AuthConfig cfg;
	private final T extcfg;
	
	/** Create a configuration set.
	 * @param cfg the authentication instance configuration.
	 * @param extcfg the external configuration.
	 */
	public AuthConfigSet(final AuthConfig cfg, final T extcfg) {
		nonNull(cfg, "cfg");
		nonNull(extcfg, "extcfg");
		this.cfg = cfg;
		this.extcfg = extcfg;
	}

	/** Get the authentication instance configuration.
	 * @return the authentication instance configuration.
	 */
	public AuthConfig getCfg() {
		return cfg;
	}

	/** Get the external configuration.
	 * @return the external configuration.
	 */
	public T getExtcfg() {
		return extcfg;
	}
	
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((cfg == null) ? 0 : cfg.hashCode());
		result = prime * result + ((extcfg == null) ? 0 : extcfg.hashCode());
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
		@SuppressWarnings("unchecked")
		AuthConfigSet<T> other = (AuthConfigSet<T>) obj;
		if (cfg == null) {
			if (other.cfg != null) {
				return false;
			}
		} else if (!cfg.equals(other.cfg)) {
			return false;
		}
		if (extcfg == null) {
			if (other.extcfg != null) {
				return false;
			}
		} else if (!extcfg.equals(other.extcfg)) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("AuthConfigSet [cfg=");
		builder.append(cfg);
		builder.append(", extcfg=");
		builder.append(extcfg);
		builder.append("]");
		return builder.toString();
	}
}
