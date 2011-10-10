package grisu.control.util;

import grisu.control.GrisuUserDetails;

import java.util.Date;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

public class AuditAdvice implements MethodInterceptor {

	public static AtomicInteger numberOfOpenMethodCalls = new AtomicInteger(0);

	static final Logger myLogger = Logger
			.getLogger(AuditAdvice.class.getName());

	public Object invoke(MethodInvocation methodInvocation) throws Throwable {

		String method = methodInvocation.getMethod().getName();
		String dn = null;
		Object[] argOs = methodInvocation.getArguments();
		String argList = "NO_ARGS";
		if ((argOs != null) && (argOs.length > 0) && !"login".equals(method)) {
			String[] args = new String[argOs.length];
			for (int i = 0; i < args.length; i++) {
				try {
					if (argOs[i] == null) {
						args[i] = "null";
					} else {
						args[i] = (argOs[i]).toString();
					}
				} catch (Exception e) {
					args[i] = "Error serializing object";
				}
			}
			argList = StringUtils.join(args, ";");
		}

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

		String tid = UUID.randomUUID().toString();

		Date start = new Date();
		int number = numberOfOpenMethodCalls.incrementAndGet();

		if (dn == null) {
			myLogger.debug("[tid: " + tid + "]: Entering method: " + method
					+ " arguments: "
					+ argList + " time: " + start.getTime()
					+ " open method calls: " + number);
		} else {
			myLogger.debug("[tid: " + tid + "]: Entering method: " + method
					+ " arguments: "
					+ argList + " user: " + dn + " time: " + start.getTime()
					+ " open method calls: " + number);
		}

		Object result = null;
		try {
			result = methodInvocation.proceed();
		} catch (Throwable t) {
			number = numberOfOpenMethodCalls.decrementAndGet();
			Date end = new Date();
			long duration = end.getTime() - start.getTime();
			myLogger.debug("[tid: " + tid + "]: Method call: " + method
					+ " failed: "
					+ t.getLocalizedMessage());
			myLogger.debug("[tid: " + tid + "]: Finished method: " + method
					+ " arguments: "
					+ argList + " time: " + end.getTime() + " duration: "
					+ duration + " open method calls: " + number);
			throw t;
		}

		number = numberOfOpenMethodCalls.decrementAndGet();

		Date end = new Date();

		long duration = end.getTime() - start.getTime();

		String resultString = "n/a";
		if (result instanceof String) {
			resultString = (String) result;
		} else if (result instanceof Integer) {
			resultString = ((Integer) result).toString();
		} else if (result instanceof Boolean) {
			resultString = ((Boolean) result).toString();
		} else if (result instanceof Long) {
			resultString = ((Long) result).toString();
		}

		resultString = resultString.replace("\n", " ");

		if (dn == null) {
			myLogger.debug("[tid: " + tid + "]: Finished method: " + method
					+ " arguments: "
					+ argList + " time: " + end.getTime() + " duration: "
					+ duration + " result: " + resultString
					+ " open method calls: " + number);
		} else {
			myLogger.debug("[tid: " + tid + "]: Finished method: " + method
					+ " arguments: "
					+ argList + " user: " + dn + " time: " + end.getTime()
					+ " duration: " + duration + " result: " + resultString
					+ " open method calls: "
					+ number);
		}

		return result;
	}

}
