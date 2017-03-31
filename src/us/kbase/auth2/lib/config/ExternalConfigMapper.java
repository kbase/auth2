package us.kbase.auth2.lib.config;

import java.util.Map;

import us.kbase.auth2.lib.config.ConfigAction.State;
import us.kbase.auth2.lib.exceptions.ExternalConfigMappingException;

/** A mapper for mapping a set of key-value pairs into an ExternalConfig class. The Authentication
 * instance uses this mapper to convert the set of key-value pairs stored in the Authentication
 * storage system into an ExternalConfig class.
 * 
 * Note that any mapper should handle the possibility that some expected key-value pairs may not be
 * defined in the Authentication storage system.
 * 
 * @author gaprice@lbl.gov
 *
 * @param <T> the type of the ExternalConfig that is the target of the mapper.
 */
public interface ExternalConfigMapper<T extends ExternalConfig> {
	
	/** Convert a set of key-value pairs into an ExternalConfig instance. 
	 * @param config the key-value pairs.
	 * @return an ExternalConfig instance.
	 * @throws ExternalConfigMappingException if the key-value pairs could not be mapped into
	 * the ExternalConfig instance.
	 */
	T fromMap(Map<String, ConfigItem<String, State>> config)
			throws ExternalConfigMappingException;
	
}
