package grisu.control;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;

public class MyProxyAuthenticationProvider extends DaoAuthenticationProvider {

	static final Logger myLogger = LoggerFactory
			.getLogger(MyProxyAuthenticationProvider.class.getName());


	@Override
	protected void additionalAuthenticationChecks(UserDetails userDetails,
			UsernamePasswordAuthenticationToken authentication)
					throws AuthenticationException {

		final GrisuUserDetails gud = (GrisuUserDetails) userDetails;
		gud.setAuthentication(authentication);

	}

}
