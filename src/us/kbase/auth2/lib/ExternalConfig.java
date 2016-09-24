package us.kbase.auth2.lib;

import java.util.Map;

//keys defined in the external config may be missing from the incoming map if they're not set in the storage engine
public interface ExternalConfig {

	//TODO JAVADOC
	
	Map<String, String> toMap();
	
}
