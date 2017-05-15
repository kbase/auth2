package us.kbase.auth2.service;

/** Represents a logger that intercepts and logs SLF4J log events.
 * 
 * Keep a reference to the object so that the auto logger is not garbage
 * collected.
 * @author gaprice@lbl.gov
 *
 */
public interface SLF4JAutoLogger {
	
	/** Set call information for the call being handled in this thread.
	 * @param method the method called.
	 * @param id the call ID.
	 * @param ipAddress the IP address of the client.
	 */
	public void setCallInfo(
			final String method,
			final String id,
			final String ipAddress);
	
	/** Get the call ID for the call being handled in this thread.
	 * @return the call ID.
	 */
	public String getCallID();
}
