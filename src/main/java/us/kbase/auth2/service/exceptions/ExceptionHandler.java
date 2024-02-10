package us.kbase.auth2.service.exceptions;

import static us.kbase.auth2.service.ContextFields.REQUEST_ID;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import javax.inject.Inject;
import javax.ws.rs.Produces;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ResourceContext;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;

import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.config.ConfigAction.State;
import us.kbase.auth2.lib.exceptions.ExternalConfigMappingException;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.service.AuthExternalConfig;
import us.kbase.auth2.service.AuthExternalConfig.AuthExternalConfigMapper;
import us.kbase.auth2.service.common.Fields;
import us.kbase.auth2.service.template.TemplateProcessor;


public class ExceptionHandler implements ExceptionMapper<Throwable> {

	//TODO TEST unit tests, probably makes sense to do logging & exceptions in the same test file
	//TODO JAVADOC
	
	@Context
	private HttpHeaders headers;
	@Inject
	private TemplateProcessor template;
	private final ObjectMapper mapper = new ObjectMapper();
	@Inject
	private Authentication auth;
	@Inject
	private ResourceInfo resourceInfo;
	@Context
	private ResourceContext resourceContext;

	@Override
	public Response toResponse(Throwable ex) {
		
		final MediaType mt = getMediaType();
		LoggerFactory.getLogger(getClass()).error("Logging exception:", ex);

		boolean includeStack = false;
		try {
			final AuthExternalConfig<State> ext = auth.getExternalConfig(
					new AuthExternalConfigMapper());
			includeStack = ext.isIncludeStackTraceInResponseOrDefault();
		} catch (AuthStorageException | ExternalConfigMappingException e) {
			LoggerFactory.getLogger(getClass()).error(
					"An error occurred in the error handler when attempting " +
					"to get the server configuration", e); 
		}
		
		final ContainerRequestContext reqContext = resourceContext.getResource(
				ContainerRequestContext.class);
		final String callID = (String) reqContext.getProperty(REQUEST_ID);
		final ErrorMessage em = new ErrorMessage(ex, callID, includeStack);
		String ret;
		if (mt.equals(MediaType.APPLICATION_JSON_TYPE)) {
			final Map<String, Object> err = new HashMap<>();
			err.put(Fields.ERROR, em);
			try {
				ret = mapper.writeValueAsString(err);
			} catch (JsonProcessingException e) {
				ret = "An error occured in the error handler when " +
						"processing the error object to JSON. " +
						"This shouldn't happen.";
				LoggerFactory.getLogger(getClass()).error(ret, e);
			}
		} else {
			ret = template.process(Fields.ERROR, em);
		}
		return Response.status(em.getHttpcode()).entity(ret).type(mt).build();
	}
	
	private final static Set<MediaType> MEDIA_SUPPORTED = new HashSet<>(Arrays.asList(
			MediaType.APPLICATION_JSON_TYPE, MediaType.TEXT_HTML_TYPE));

	private MediaType getMediaType() {
		Optional<MediaType> mt = getMediaTypeFromHeaders(headers);
		if (!mt.isPresent()) {
			mt = getMediaTypeFromMethodAnnotation(resourceInfo);
		}
		if (!mt.isPresent()) {
			mt = Optional.of(MediaType.TEXT_HTML_TYPE);
		}
		return mt.get();
	}

	private Optional<MediaType> getMediaTypeFromMethodAnnotation(final ResourceInfo resourceInfo) {
		
		final Optional<Method> method = Optional.ofNullable(
				resourceInfo.getResourceMethod());
		if (!method.isPresent()) {
			return Optional.empty();
		}
		Optional<Produces> produces = Optional.ofNullable(
				method.get().getAnnotation(Produces.class));
		if (!produces.isPresent()) {
			final Class<?> cls = resourceInfo.getResourceClass();
			produces = Optional.ofNullable((Produces) cls.getAnnotation(Produces.class));
		}
		if (!produces.isPresent()) {
			return Optional.empty();
		}
		final List<String> mediaTypes = new LinkedList<>();
		for (final String mtlist: produces.get().value()) { // comma separated list
			for (final String mt: mtlist.split(",")) {
				mediaTypes.add(mt.trim());
			}
		}
		for (final String mtype: mediaTypes) {
			final MediaType putativeType;
			try {
				putativeType = MediaType.valueOf(mtype);
			} catch (IllegalArgumentException e) {
				// this might be impossible if JAX-RS validates the method annotations...
				LoggerFactory.getLogger(getClass()).error(String.format(
						"Invalid @Produces annotation on method %s: %s",
						method.get().toGenericString(), mtype));
				continue; // an else block like python would be nice here
			}
			if (MEDIA_SUPPORTED.contains(putativeType)) {
				return Optional.of(putativeType);
			} else {
				LoggerFactory.getLogger(getClass()).error(String.format(
						"Unsupported @Produces annotation on method %s: %s",
						method.get().toGenericString(), mtype));
			}
		}
		return Optional.empty();
	}

	/* JAX-RS will cause an error to be thrown if the Accept header does not contain a supported
	 * media type, so we can ignore any unsupported types here
	 */
	private Optional<MediaType> getMediaTypeFromHeaders(final HttpHeaders headers) {
		//sorted by q-value
		final Optional<List<MediaType>> mtypes = Optional.ofNullable(
				headers.getAcceptableMediaTypes());
		if (mtypes.isPresent()) {
			for (final MediaType m: mtypes.get()) {
				if (MEDIA_SUPPORTED.contains(m)) {
					return Optional.of(m);
				}
			}
		}
		return Optional.empty();
	}
}
