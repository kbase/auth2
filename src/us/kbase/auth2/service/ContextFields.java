package us.kbase.auth2.service;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerResponseContext;

/** Field names for items added to request or response context objects.
 * 
 * @see ContainerRequestContext
 * @see ContainerResponseContext
 *
 */
public class ContextFields {

	/** The ID of a request. Type must be String. */
	public final static String REQUEST_ID = "request_id";
	
}
