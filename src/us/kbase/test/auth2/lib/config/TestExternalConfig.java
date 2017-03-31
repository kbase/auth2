package us.kbase.test.auth2.lib.config;

import java.util.HashMap;
import java.util.Map;

import com.google.common.collect.ImmutableMap;

import us.kbase.auth2.lib.config.ConfigAction;
import us.kbase.auth2.lib.config.ConfigAction.Action;
import us.kbase.auth2.lib.config.ConfigAction.State;
import us.kbase.auth2.lib.config.ConfigItem;
import us.kbase.auth2.lib.config.ExternalConfig;
import us.kbase.auth2.lib.config.ExternalConfigMapper;
import us.kbase.auth2.lib.exceptions.ExternalConfigMappingException;

public class TestExternalConfig<T extends ConfigAction> implements ExternalConfig {
		
	public final ConfigItem<String, T> aThing;
	
	
	public TestExternalConfig(final ConfigItem<String, T> thing) {
		aThing = thing;
	}

	@Override
	public Map<String, ConfigItem<String, Action>> toMap() {
		final ConfigItem<String, Action> item;
		if (aThing.getAction().isRemove()) {
			item = ConfigItem.remove();
		} else if (aThing.getAction().isSet()) {
			item = ConfigItem.set(aThing.getItem());
		} else if (aThing.getAction().isNoAction()) {
			item = ConfigItem.noAction(); // just here to test mongostorage no action
		} else {
			return new HashMap<>();
		}
		return ImmutableMap.of("thing", item);
	}
	
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((aThing == null) ? 0 : aThing.hashCode());
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
		TestExternalConfig<?> other = (TestExternalConfig<?>) obj;
		if (aThing == null) {
			if (other.aThing != null) {
				return false;
			}
		} else if (!aThing.equals(other.aThing)) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("TestExternalConfig [aThing=");
		builder.append(aThing);
		builder.append("]");
		return builder.toString();
	}

	public static class TestExternalConfigMapper implements
			ExternalConfigMapper<TestExternalConfig<State>> {

		@Override
		public TestExternalConfig<State> fromMap(
				final Map<String, ConfigItem<String, State>> config)
				throws ExternalConfigMappingException {
			
			return new TestExternalConfig<>(config.get("thing"));
		}
	}
}
