package grisu.control;

import grisu.backend.model.ProxyCredential;
import grisu.backend.model.User;
import grisu.backend.utils.CertHelpers;
import grisu.control.exceptions.NoValidCredentialException;
import grisu.control.serviceInterfaces.AbstractServiceInterface;
import grisu.jcommons.utils.MyProxyServerParams;
import grisu.settings.ServerPropertiesManager;

import java.util.Set;

import org.globus.myproxy.CredentialInfo;
import org.globus.myproxy.MyProxy;
import org.ietf.jgss.GSSCredential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.GrantedAuthorityImpl;
import org.springframework.security.core.userdetails.UserDetails;

import com.google.common.collect.Sets;

public class GrisuUserDetails implements UserDetails {

	static final Logger myLogger = LoggerFactory
			.getLogger(GrisuUserDetails.class.getName());

	private final String username;
	private UsernamePasswordAuthenticationToken authentication;
	private final boolean success = true;
	private ProxyCredential proxy = null;

	private User user = null;

	public GrisuUserDetails(String username) {
		myLogger.debug("Creating GrisuUserDetails object for " + username);
		this.username = username;
	}

	private synchronized ProxyCredential createProxyCredential(String username,
			String password, String myProxyServer, int port, int lifetime) {

		// System.out.println("Username: "+username);
		// System.out.println("Password: "+password);

		final MyProxy myproxy = new MyProxy(myProxyServer, port);
		GSSCredential proxy = null;
		try {
			myLogger.debug("Getting delegated proxy from MyProxy...");
			proxy = myproxy.get(username, password, lifetime);
			final int remaining = proxy.getRemainingLifetime();
			myLogger.debug("Finished getting delegated proxy from MyProxy. DN: "
					+ CertHelpers.getDnInProperFormat(proxy)
					+ " remaining liftime: " + remaining);

			if (remaining <= 0) {
				throw new RuntimeException("Proxy not valid anymore.");
			}

			return new ProxyCredential(proxy);
		} catch (final Exception e) {
			myLogger.error(
					"Could not create myproxy credential: "
							+ e.getLocalizedMessage(), e);
			throw new NoValidCredentialException(e.getLocalizedMessage());
		}

	}

	public Set<GrantedAuthority> getAuthorities() {

		if (success) {
			final Set<GrantedAuthority> result = Sets.newHashSet();
			result.add(new GrantedAuthorityImpl("User"));
			return result;
		} else {
			return null;
		}

	}

	public synchronized long getCredentialEndTime() {

		if (authentication == null) {
			return -1;
		}

		final MyProxy myproxy = new MyProxy(
				MyProxyServerParams.getMyProxyServer(),
				MyProxyServerParams.getMyProxyPort());
		CredentialInfo info = null;
		try {
			final String user = authentication.getPrincipal().toString();
			final String password = authentication.getCredentials().toString();
			info = myproxy.info(getProxyCredential().getGssCredential(), user,
					password);
		} catch (final Exception e) {
			myLogger.error(e.getLocalizedMessage(), e);
			return -1;
		}

		return info.getEndTime();

	}

	public String getPassword() {

		return "dummy";
	}

	public synchronized ProxyCredential getProxyCredential()
			throws AuthenticationException {

		// myLogger.debug("Getting proxy credential...");

		if (authentication == null) {
			throw new AuthenticationException("No authentication token set.") {
			};
		}

		if ((proxy != null) && proxy.isValid()) {

			// myLogger.debug("Old valid proxy found.");
			long oldLifetime = -1;
			try {
				oldLifetime = proxy.getGssCredential().getRemainingLifetime();
				if (oldLifetime >= ServerPropertiesManager
						.getMinProxyLifetimeBeforeGettingNewProxy()) {

					// myLogger.debug("Proxy still valid and long enough lifetime.");
					// myLogger.debug("Old valid proxy still good enough. Using it.");
					return proxy;
				}
			} catch (final Exception e) {
				myLogger.error(e.getLocalizedMessage(), e);
			}
			// myLogger.debug("Old proxy not good enough. Creating new one...");
		}

		ProxyCredential proxyTemp = null;
		try {
			proxyTemp = createProxyCredential(authentication.getPrincipal()
					.toString(), authentication.getCredentials().toString(),
					MyProxyServerParams.DEFAULT_MYPROXY_SERVER,
					MyProxyServerParams.DEFAULT_MYPROXY_PORT,
					ServerPropertiesManager.getMyProxyLifetime());
		} catch (final NoValidCredentialException e) {
			throw new AuthenticationException(e.getLocalizedMessage(), e) {
			};
		}

		if ((proxyTemp == null) || !proxyTemp.isValid()) {

			// if ( proxyTemp == null ) {
			// System.out.println("PROXYTEMP IS NULL");
			// } else {
			// if ( proxyTemp.getGssCredential() == null ) {
			// System.out.println("GSSCREDENTIAL IS NULL");
			// } else {
			// System.out.println("GSSCREDENTIAL NO LIFETIME");
			// }
			// }

			throw new AuthenticationException(
					"Could not get valid myproxy credential.") {
			};
		} else {
			// myLogger.info("Authentication successful.");
			this.proxy = proxyTemp;
			return this.proxy;
		}

	}

	public synchronized User getUser(AbstractServiceInterface si) {

		if (user == null) {
			user = User.createUser(getProxyCredential(), si);
		}

		user.setCred(getProxyCredential());
		return user;

	}

	public String getUsername() {
		return username;
	}

	public boolean isAccountNonExpired() {
		return success;
	}

	public boolean isAccountNonLocked() {
		return success;
	}

	public boolean isCredentialsNonExpired() {
		return success;
	}

	public boolean isEnabled() {
		return success;
	}

	public void setAuthentication(
			UsernamePasswordAuthenticationToken authentication) {
		this.authentication = authentication;
		getProxyCredential();
	}

}
