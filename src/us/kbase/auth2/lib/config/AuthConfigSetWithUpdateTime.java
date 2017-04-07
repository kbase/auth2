package us.kbase.auth2.lib.config;

/** An authorization configuration set including how often the configuration is pulled from the 
 * database. This update time determines how long it will take other authentication instances
 * that use the same database to get any configuration updates.
 * @author gaprice@lbl.gov
 *
 * @param <T> the type of the external configuration class.
 */
public class AuthConfigSetWithUpdateTime<T extends ExternalConfig> extends AuthConfigSet<T> {
	
	private final int updateTimeInMillis;
	
	/** Create a new config set.
	 * @param cfg the authorization configuration.
	 * @param extcfg the external configuration.
	 * @param updateTimeInMillis the update time in milliseconds.
	 */
	public AuthConfigSetWithUpdateTime(
			final AuthConfig cfg,
			final T extcfg,
			final int updateTimeInMillis) {
		super(cfg, extcfg);
		this.updateTimeInMillis = updateTimeInMillis;
	}

	/** Get the update time in milliseconds.
	 * @return the update time.
	 */
	public int getUpdateTimeInMillis() {
		return updateTimeInMillis;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + updateTimeInMillis;
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!super.equals(obj)) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		AuthConfigSetWithUpdateTime<?> other = (AuthConfigSetWithUpdateTime<?>) obj;
		if (updateTimeInMillis != other.updateTimeInMillis) {
			return false;
		}
		return true;
	}
}
