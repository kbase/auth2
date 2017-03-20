package us.kbase.auth2.lib.config;

import java.util.Map;

/** A configuration external to the Authentication instance. As a convenience, the Authorization
 * instance allows storing arbitrary configurations as key value pairs in Authorization
 * storage.
 * 
 * @author gaprice@lbl.gov
 *
 */
public interface ExternalConfig {

	/** Generate a set of key value pairs from the configuration; these pairs will be stored in
	 * the authorization storage system.
	 * @return a map of configuration key value pairs.
	 */
	Map<String, String> toMap();
	
}
