package us.kbase.auth2.service;

import java.io.IOException;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.ContainerResponseContext;
import javax.ws.rs.container.ContainerResponseFilter;
import javax.ws.rs.core.Context;

import org.slf4j.LoggerFactory;

import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.config.ConfigAction.ConfigState;
import us.kbase.auth2.lib.exceptions.ExternalConfigMappingException;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.service.AuthExternalConfig.AuthExternalConfigMapper;

public class LoggingFilter implements ContainerRequestFilter,
		ContainerResponseFilter {
	
	//TODO TEST unit tests
	//TODO JAVADOC
	
	private static final String X_FORWARDED_FOR = "X-Forwarded-For";
	private static final String X_REAL_IP = "X-Real-IP";
	private static final String USER_AGENT = "User-Agent";
	
	@Context
	private HttpServletRequest servletRequest;
	
	@Inject
	private SLF4JAutoLogger logger;
	@Inject
	private Authentication auth;
	
	@Override
	public void filter(final ContainerRequestContext reqcon)
			throws IOException {
		boolean ignoreIPheaders = true;
		try {
			final AuthExternalConfig<ConfigState> ext = auth.getExternalConfig(
					new AuthExternalConfigMapper());
			ignoreIPheaders = ext.isIgnoreIPHeadersOrDefault();
		} catch (AuthStorageException | ExternalConfigMappingException e) {
			LoggerFactory.getLogger(getClass()).error(
					"An error occurred in the logger when attempting " +
					"to get the server configuration", e); 
		}
		logger.setCallInfo(reqcon.getMethod(),
				("" + Math.random()).substring(2),
				getIpAddress(reqcon, ignoreIPheaders));
	}
	
	//TODO TEST xff and realip headers
	public String getIpAddress(
			final ContainerRequestContext request,
			final boolean ignoreIPsInHeaders) {
		final String xFF = request.getHeaderString(X_FORWARDED_FOR);
		final String realIP = request.getHeaderString(X_REAL_IP);

		if (!ignoreIPsInHeaders) {
			if (xFF != null && !xFF.isEmpty()) {
				return xFF.split(",")[0].trim();
			}
			if (realIP != null && !realIP.isEmpty()) {
				return realIP.trim();
			}
		}
		return servletRequest.getRemoteAddr();
	}

	@Override
	public void filter(
			final ContainerRequestContext reqcon,
			final ContainerResponseContext rescon)
			throws IOException {
		LoggerFactory.getLogger(getClass()).info("{} {} {} {}",
				reqcon.getMethod(),
				reqcon.getUriInfo().getAbsolutePath(),
				rescon.getStatus(),
				reqcon.getHeaderString(USER_AGENT));
	}

}
