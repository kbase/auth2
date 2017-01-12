package us.kbase.auth2.lib;

/** A configuration set for the authentication instance. Contains the configuration of the
 * authentication instance and a user-definable external configuration that is stored as key-value
 * configuration values in the authentication storage.
 * @author gaprice@lbl.gov
 *
 * @param <T> the external configuration.
 */
public class AuthConfigSet<T extends ExternalConfig> {

	//TODO TEST
	
	private AuthConfig cfg;
	private T extcfg;
	
	/** Create a configuration set.
	 * @param cfg the authentication instance configuration.
	 * @param extcfg the external configuration.
	 */
	public AuthConfigSet(final AuthConfig cfg, final T extcfg) {
		if (cfg == null) {
			throw new NullPointerException("cfg");
		}
		if (extcfg == null) {
			throw new NullPointerException("extcfg");
		}
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
