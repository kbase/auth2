package us.kbase.auth2.service.exceptions;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.inject.Inject;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;
import javax.ws.rs.ext.ExceptionMapper;

import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.exceptions.ExternalConfigMappingException;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.service.AuthExternalConfig;
import us.kbase.auth2.service.AuthExternalConfig.AuthExternalConfigMapper;
import us.kbase.auth2.service.SLF4JAutoLogger;
import us.kbase.auth2.service.template.TemplateProcessor;


public class ExceptionHandler implements ExceptionMapper<Throwable> {

	//TODO TEST unit tests
	//TODO JAVADOC
	
	@Context
	private HttpHeaders headers;
	@Inject
	private TemplateProcessor template;
	private final ObjectMapper mapper = new ObjectMapper();
	@Inject
	private SLF4JAutoLogger logger;
	@Inject
	private Authentication auth;
	@Inject
	private UriInfo uriInfo;

	@Override
	public Response toResponse(Throwable ex) {
		
		MediaType mt = getMediaType();
		//TODO CODE this is a gross hack. Really want to know the produces annotation for the method that threw the error
		if (mt == null) {
			if (uriInfo.getPath().startsWith("api")) {
				mt = MediaType.APPLICATION_JSON_TYPE;
			} else {
				mt = MediaType.TEXT_HTML_TYPE;
			}
		}
		LoggerFactory.getLogger(getClass()).error("Logging exception:", ex);

		boolean includeStack = false;
		try {
			final AuthExternalConfig ext = auth.getExternalConfig(
					new AuthExternalConfigMapper());
			includeStack = ext.isIncludeStackTraceInResponse();
		} catch (AuthStorageException | ExternalConfigMappingException e) {
			LoggerFactory.getLogger(getClass()).error(
					"An error occurred in the error handler when attempting " +
					"to get the server configuration", e); 
		}
		final ErrorMessage em = new ErrorMessage(ex, logger.getCallID(),
				includeStack);
		String ret;
		if (mt.equals(MediaType.APPLICATION_JSON_TYPE)) {
			final Map<String, Object> err = new HashMap<>();
			err.put("error", em);
			try {
				ret = mapper.writeValueAsString(err);
			} catch (JsonProcessingException e) {
				ret = "An error occured in the error handler when " +
						"processing the error object to JSON. " +
						"This shouldn't happen.";
				LoggerFactory.getLogger(getClass()).error(ret, e);
			}
		} else {
			ret = template.process("error", em);
		}
		return Response.status(em.getHttpCode()).entity(ret).type(mt).build();
	}

	// either html or json
	private MediaType getMediaType() {
		MediaType mt = null;
		//sorted by q-value
		final List<MediaType> mtypes = headers.getAcceptableMediaTypes();
		if (mtypes != null) {
			for (final MediaType m: mtypes) {
				if (m.equals(MediaType.TEXT_HTML_TYPE) ||
						m.equals(MediaType.APPLICATION_JSON_TYPE)) {
					mt = m;
					break;
				}
			}
		}
		return mt;
	}
}
