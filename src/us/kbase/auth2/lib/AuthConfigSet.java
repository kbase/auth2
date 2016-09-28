package us.kbase.auth2.lib;

public class AuthConfigSet<T extends ExternalConfig> {

	//TODO TEST
	//TODO JAVADOC
	
	private AuthConfig cfg;
	private T extcfg;
	
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

	public AuthConfig getCfg() {
		return cfg;
	}

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
