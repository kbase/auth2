package us.kbase.auth2.service.ui;

import java.util.Map;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import org.glassfish.jersey.server.mvc.Template;

import us.kbase.auth2.service.common.ServiceCommon;

@Path(UIPaths.ROOT)
public class Root {
	
	//TODO JAVADOC or swagger
	
	@GET
	@Template(name = "/root")
	@Produces(MediaType.TEXT_HTML)
	public Map<String, Object> rootHTML() {
		return ServiceCommon.root();
	}
	
	@GET
	@Produces(MediaType.APPLICATION_JSON)
	public Map<String, Object> rootJSON() {
		return ServiceCommon.root();
	}
}
