package grisu.control.util;

import grisu.control.GrisuUserDetails;

import java.util.Date;

import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

public class AuditAdvice implements MethodInterceptor {

	static final Logger myLogger = Logger
			.getLogger(AuditAdvice.class.getName());

	public Object invoke(MethodInvocation methodInvocation) throws Throwable {

		String method = methodInvocation.getMethod().getName();
		String dn = null;
		Object[] argOs = methodInvocation.getArguments();
		String[] args = new String[argOs.length];
		for (int i = 0; i < args.length; i++) {
			args[i] = (argOs[i]).toString();
		}

		String argList = StringUtils.join(args, ";");

		final SecurityContext securityContext = SecurityContextHolder
				.getContext();
		final Authentication authentication = securityContext
				.getAuthentication();

		if (authentication != null) {
			final Object principal = authentication.getPrincipal();
			if (principal instanceof GrisuUserDetails) {
				GrisuUserDetails gud = (GrisuUserDetails) principal;
				dn = gud.getProxyCredential().getDn();
			}
		}

		Date start = new Date();

		if (dn == null) {
			myLogger.debug("Entering method: " + method + " arguments: "
					+ argList + " time: "
					+ start.getTime());
		} else {
			myLogger.debug("Entering method: " + method + " arguments: "
					+ argList + " user: " + dn
					+ " time: " + start.getTime());
		}

		Object result = methodInvocation.proceed();

		Date end = new Date();

		long duration = end.getTime() - start.getTime();

		if (dn == null) {
			myLogger.debug("Finished method: " + method + " arguments: "
					+ argList + " time: "
					+ end.getTime() + " duration: " + duration);
		} else {
			myLogger.debug("Finished method: " + method + " arguments: "
					+ argList + " user: " + dn
					+ " time: " + end.getTime() + " duration: " + duration);
		}

		return result;
	}

}
