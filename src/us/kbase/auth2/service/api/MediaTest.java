package us.kbase.auth2.service.api;

import java.util.HashMap;
import java.util.Map;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import org.glassfish.jersey.server.mvc.Template;

@Path("/thing/mediatest")
public class MediaTest {
	
	/* if there's a @Template for the method always returns html regardless of Accept: header
	 * and the media types supported (JSON tested here). Have to split HTML and JSON into
	 * separate methods.
	 */
	
	@GET
	@Template(name = "/logout")
	@Produces({MediaType.TEXT_HTML})
	public Map<String, Object> fooHTML() {
		final Map<String, Object> ret = new HashMap<>();
		ret.put("user", "foo");
		ret.put("logouturl", "bar");
		return ret;
	}
	
	@GET
	@Produces({MediaType.APPLICATION_JSON})
	public Map<String, Object> fooJSON() {
		final Map<String, Object> ret = new HashMap<>();
		ret.put("user", "foo");
		ret.put("logouturl", "bar");
		return ret;
	}
}
