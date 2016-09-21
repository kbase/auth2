package us.kbase.auth2.service.exceptions;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.inject.Inject;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;

import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

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

	@Override
	public Response toResponse(Throwable ex) {

		final MediaType mt = getMediaType();
		LoggerFactory.getLogger(getClass()).error("Logging exception:", ex);

		//TODO AUTH make including trace configurable
		final ErrorMessage em = new ErrorMessage(ex, logger.getCallID(), true);
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
		if (mt == null) {
			mt = MediaType.TEXT_HTML_TYPE;
		}
		return mt;
	}
}
