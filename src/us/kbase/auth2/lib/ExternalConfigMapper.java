package us.kbase.auth2.lib;

import java.util.Map;

import us.kbase.auth2.lib.exceptions.ExternalConfigMappingException;

// keys defined in the external config may be missing from the incoming map if they're not set in the storage engine
public interface ExternalConfigMapper<T extends ExternalConfig> {

	//TODO JAVADOC
	
	T fromMap(Map<String, String> config)
			throws ExternalConfigMappingException;
	
}
