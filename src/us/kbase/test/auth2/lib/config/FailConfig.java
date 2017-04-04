package us.kbase.test.auth2.lib.config;

import java.util.Map;

import us.kbase.auth2.lib.config.ConfigAction.Action;
import us.kbase.auth2.lib.config.ConfigAction.State;
import us.kbase.auth2.lib.config.ConfigItem;
import us.kbase.auth2.lib.config.ExternalConfig;
import us.kbase.auth2.lib.config.ExternalConfigMapper;
import us.kbase.auth2.lib.exceptions.ExternalConfigMappingException;

public class FailConfig implements ExternalConfig {

	@Override
	public Map<String, ConfigItem<String, Action>> toMap() {
		throw new UnsupportedOperationException();
	}

	public static class FailingMapper implements ExternalConfigMapper<FailConfig> {

		@Override
		public FailConfig fromMap(final Map<String, ConfigItem<String, State>> config)
				throws ExternalConfigMappingException {
			throw new ExternalConfigMappingException("always fails");
		}
		
	}
}
