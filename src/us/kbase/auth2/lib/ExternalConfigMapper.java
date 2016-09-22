package us.kbase.auth2.lib;

import java.util.Map;

import us.kbase.auth2.lib.exceptions.ExternalConfigMappingException;

public interface ExternalConfigMapper {

	//TODO JAVADOC
	
	ExternalConfig fromMap(Map<String, String> config)
			throws ExternalConfigMappingException;
	
}
