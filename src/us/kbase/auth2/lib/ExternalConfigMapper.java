package us.kbase.auth2.lib;

import java.util.Map;

import us.kbase.auth2.lib.exceptions.ExternalConfigMappingException;

public interface ExternalConfigMapper<T extends ExternalConfig> {

	//TODO JAVADOC
	
	T fromMap(Map<String, String> config)
			throws ExternalConfigMappingException;
	
}
