package us.kbase.auth2.lib.config;

import static java.util.Objects.requireNonNull;

import java.util.Map;

import us.kbase.auth2.lib.config.ConfigAction.Action;
import us.kbase.auth2.lib.config.ConfigAction.State;
import us.kbase.auth2.lib.exceptions.ExternalConfigMappingException;

/** An external configuration stored as a map. The corresponding mapper simply stores the map
 * directly in the configuration class, rather than transforming the map into the class.
 * @author gaprice@lbl.gov
 *
 */
public class CollectingExternalConfig implements ExternalConfig {
	
	private final Map<String, ConfigItem<String, State>> cfg;
	
	/** Create a new configuration.
	 * @param map the map defining the configuration.
	 */
	public CollectingExternalConfig(final Map<String, ConfigItem<String, State>> map) {
		requireNonNull(map, "map");
		cfg = map;
	}
	
	@Override
	public Map<String, ConfigItem<String, Action>> toMap() {
		throw new UnsupportedOperationException();
	}
	
	/** Get the collected map.
	 * @return the map.
	 */
	public Map<String, ConfigItem<String, State>> getMap() {
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
		public CollectingExternalConfig fromMap(
				final Map<String, ConfigItem<String, State>> config)
				throws ExternalConfigMappingException {
			return new CollectingExternalConfig(config);
		}
	}
}