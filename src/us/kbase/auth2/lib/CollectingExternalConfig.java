package us.kbase.auth2.lib;

import java.util.Map;

import us.kbase.auth2.lib.exceptions.ExternalConfigMappingException;

/** An external configuration stored as a map. The corresponding mapper simply stores the map
 * directly in the configuration class, rather than transforming the map into the class.
 * @author gaprice@lbl.gov
 *
 */
public class CollectingExternalConfig implements ExternalConfig {
	
	private final Map<String, String> cfg;
	
	/** Create a new configuration.
	 * @param map the map defining the configuration.
	 */
	public CollectingExternalConfig(final Map<String, String> map) {
		//TODO CODE should probably check for null here
		cfg = map;
	}
	
	@Override
	public Map<String, String> toMap() {
		return cfg;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((cfg == null) ? 0 : cfg.hashCode());
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
		CollectingExternalConfig other = (CollectingExternalConfig) obj;
		if (cfg == null) {
			if (other.cfg != null) {
				return false;
			}
		} else if (!cfg.equals(other.cfg)) {
			return false;
		}
		return true;
	}

	/** A mapper that transforms a map into a collecting external configuration.
	 * @author gaprice@lbl.gov
	 *
	 */
	public static class CollectingExternalConfigMapper implements
			ExternalConfigMapper<CollectingExternalConfig> {

		@Override
		public CollectingExternalConfig fromMap(final Map<String, String> config)
				throws ExternalConfigMappingException {
			return new CollectingExternalConfig(config);
		}
	}
}