package us.kbase.test.auth2.lib.config;

import java.util.HashMap;
import java.util.Map;

import us.kbase.auth2.lib.config.ExternalConfig;
import us.kbase.auth2.lib.config.ExternalConfigMapper;
import us.kbase.auth2.lib.exceptions.ExternalConfigMappingException;

public class TestExternalConfig implements ExternalConfig {
		
	public final String aThing;
	
	public TestExternalConfig(final String thing) {
		aThing = thing;
	}

	@Override
	public Map<String, String> toMap() {
		final Map<String, String> ret = new HashMap<>();
		ret.put("thing", aThing);
		return ret;
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
		TestExternalConfig other = (TestExternalConfig) obj;
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
			ExternalConfigMapper<TestExternalConfig> {

		@Override
		public TestExternalConfig fromMap(final Map<String, String> config)
				throws ExternalConfigMappingException {
			return new TestExternalConfig(config.get("thing"));
		}
	}
	
}
