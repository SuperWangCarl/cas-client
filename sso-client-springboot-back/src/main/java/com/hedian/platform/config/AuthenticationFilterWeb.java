package com.hedian.platform.config;

import com.hedian.platform.bean.CasConfig;
import com.hedian.platform.utils.JsonUtil;
import org.jasig.cas.client.Protocol;
import org.jasig.cas.client.authentication.AuthenticationRedirectStrategy;
import org.jasig.cas.client.authentication.ContainsPatternUrlPatternMatcherStrategy;
import org.jasig.cas.client.authentication.DefaultAuthenticationRedirectStrategy;
import org.jasig.cas.client.authentication.DefaultGatewayResolverImpl;
import org.jasig.cas.client.authentication.ExactUrlPatternMatcherStrategy;
import org.jasig.cas.client.authentication.GatewayResolver;
import org.jasig.cas.client.authentication.RegexUrlPatternMatcherStrategy;
import org.jasig.cas.client.authentication.UrlPatternMatcherStrategy;
import org.jasig.cas.client.configuration.ConfigurationKeys;
import org.jasig.cas.client.util.AbstractCasFilter;
import org.jasig.cas.client.util.CommonUtils;
import org.jasig.cas.client.util.ReflectUtils;
import org.jasig.cas.client.validation.Assertion;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;

/**
 * @ClassName: AuthenticationFilterWeb
 * @Description: 前后端分离的认证
 * @Auther: SuperWang
 * @Date: 2019/3/28 15:07
 * @Vsersion: 0.0.1
 */
public class AuthenticationFilterWeb extends AbstractCasFilter {
	/**
	 * The URL to the CAS Server login.
	 */
	private String casServerLoginUrl;

	/**
	 * Whether to send the renew request or not.
	 */
	private boolean renew = false;

	/**
	 * Whether to send the gateway request or not.
	 */
	private boolean gateway = false;

	private GatewayResolver gatewayStorage = new DefaultGatewayResolverImpl();

	private AuthenticationRedirectStrategy authenticationRedirectStrategy = new DefaultAuthenticationRedirectStrategy();

	private UrlPatternMatcherStrategy ignoreUrlPatternMatcherStrategyClass = null;

	private static final Map<String, Class<? extends UrlPatternMatcherStrategy>> PATTERN_MATCHER_TYPES =
			new HashMap<String, Class<? extends UrlPatternMatcherStrategy>>();

	static {
		PATTERN_MATCHER_TYPES.put("CONTAINS", ContainsPatternUrlPatternMatcherStrategy.class);
		PATTERN_MATCHER_TYPES.put("REGEX", RegexUrlPatternMatcherStrategy.class);
		PATTERN_MATCHER_TYPES.put("EXACT", ExactUrlPatternMatcherStrategy.class);
	}

	public AuthenticationFilterWeb() {
		this(Protocol.CAS2);
	}

	protected AuthenticationFilterWeb(final Protocol protocol) {
		super(protocol);
	}

	protected void initInternal(final FilterConfig filterConfig) throws ServletException {
		if (!isIgnoreInitConfiguration()) {
			super.initInternal(filterConfig);
			setCasServerLoginUrl(getString(ConfigurationKeys.CAS_SERVER_LOGIN_URL));
			setRenew(getBoolean(ConfigurationKeys.RENEW));
			setGateway(getBoolean(ConfigurationKeys.GATEWAY));

			final String ignorePattern = getString(ConfigurationKeys.IGNORE_PATTERN);
			final String ignoreUrlPatternType = getString(ConfigurationKeys.IGNORE_URL_PATTERN_TYPE);

			if (ignorePattern != null) {
				final Class<? extends UrlPatternMatcherStrategy> ignoreUrlMatcherClass = PATTERN_MATCHER_TYPES.get(ignoreUrlPatternType);
				if (ignoreUrlMatcherClass != null) {
					this.ignoreUrlPatternMatcherStrategyClass = ReflectUtils.newInstance(ignoreUrlMatcherClass.getName());
				} else {
					try {
						logger.trace("Assuming {} is a qualified class name...", ignoreUrlPatternType);
						this.ignoreUrlPatternMatcherStrategyClass = ReflectUtils.newInstance(ignoreUrlPatternType);
					} catch (final IllegalArgumentException e) {
						logger.error("Could not instantiate class [{}]", ignoreUrlPatternType, e);
					}
				}
				if (this.ignoreUrlPatternMatcherStrategyClass != null) {
					this.ignoreUrlPatternMatcherStrategyClass.setPattern(ignorePattern);
				}
			}

			final Class<? extends GatewayResolver> gatewayStorageClass = getClass(ConfigurationKeys.GATEWAY_STORAGE_CLASS);

			if (gatewayStorageClass != null) {
				setGatewayStorage(ReflectUtils.newInstance(gatewayStorageClass));
			}

			final Class<? extends AuthenticationRedirectStrategy> authenticationRedirectStrategyClass = getClass(ConfigurationKeys.AUTHENTICATION_REDIRECT_STRATEGY_CLASS);

			if (authenticationRedirectStrategyClass != null) {
				this.authenticationRedirectStrategy = ReflectUtils.newInstance(authenticationRedirectStrategyClass);
			}
		}
	}

	public void init() {
		super.init();
		CommonUtils.assertNotNull(this.casServerLoginUrl, "casServerLoginUrl cannot be null.");
	}

	public final void doFilter(final ServletRequest servletRequest, final ServletResponse servletResponse,
							   final FilterChain filterChain) throws IOException, ServletException {

		final HttpServletRequest request = (HttpServletRequest) servletRequest;
		final HttpServletResponse response = (HttpServletResponse) servletResponse;
		//获取前端的地址 存入 context 中
		String origin = request.getHeader("Origin");
		//配置允许跨域
		response.setHeader("Access-control-Allow-Origin", request.getHeader("Origin"));
		response.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS,PUT,DELETE");
		response.setHeader("Access-Control-Allow-Headers", request.getHeader("Access-Control-Request-Headers"));
		response.setHeader("Access-Control-Allow-Credentials", "true");

		// 跨域时会首先发送一个 option 请求，这里我们给option请求直接返回正常状态
		if (request.getMethod().equals(RequestMethod.OPTIONS.name())) {
			response.setStatus(HttpStatus.OK.value());
			return;
		}
		if (isRequestUrlExcluded(request)) {
			logger.debug("Request is ignored.");
			filterChain.doFilter(request, response);
			return;
		}

		final HttpSession session = request.getSession(false);
		final Assertion assertion = session != null ? (Assertion) session.getAttribute(CONST_CAS_ASSERTION) : null;

		if (assertion != null) {
			//此时获取不到 Origin地址表示是从地址栏直接访问的 进行重定向到 前台
			if (origin == null) {
				response.sendRedirect(CasConfig.clientWebUrl);
				return;
			}
			filterChain.doFilter(request, response);
			return;
		}

		final String serviceUrl = constructServiceUrl(request, response);
		final String ticket = retrieveTicketFromRequest(request);
		final boolean wasGatewayed = this.gateway && this.gatewayStorage.hasGatewayedAlready(request, serviceUrl);

		if (CommonUtils.isNotBlank(ticket) || wasGatewayed) {
			filterChain.doFilter(request, response);
			return;
		}

		final String modifiedServiceUrl;

		logger.debug("no ticket and no assertion found");
		if (this.gateway) {
			logger.debug("setting gateway attribute in session");
			modifiedServiceUrl = this.gatewayStorage.storeGatewayInformation(request, serviceUrl);
		} else {
			modifiedServiceUrl = serviceUrl;
		}

		logger.debug("Constructed service url: {}", modifiedServiceUrl);

		final String urlToRedirectTo = CommonUtils.constructRedirectUrl(this.casServerLoginUrl,
				getProtocol().getServiceParameterName(), modifiedServiceUrl, this.renew, this.gateway);

		logger.debug("redirecting to \"{}\"", urlToRedirectTo);

		//this.authenticationRedirectStrategy.redirect(request, response, urlToRedirectTo);

		//返回给前端 url 让前端重定向都该地址
		response.setContentType("application/json; charset=utf-8");
		PrintWriter out = response.getWriter();
		HashMap<String, String> map = new HashMap<>();
		map.put("flag", "redict");
		map.put("urlToRedirectTo", urlToRedirectTo);
		out.print(JsonUtil.Object2JsonString(map));
		out.flush();
		out.close();
	}

	public final void setRenew(final boolean renew) {
		this.renew = renew;
	}

	public final void setGateway(final boolean gateway) {
		this.gateway = gateway;
	}

	public final void setCasServerLoginUrl(final String casServerLoginUrl) {
		this.casServerLoginUrl = casServerLoginUrl;
	}

	public final void setGatewayStorage(final GatewayResolver gatewayStorage) {
		this.gatewayStorage = gatewayStorage;
	}

	private boolean isRequestUrlExcluded(final HttpServletRequest request) {
		if (this.ignoreUrlPatternMatcherStrategyClass == null) {
			return false;
		}

		final StringBuffer urlBuffer = request.getRequestURL();
		if (request.getQueryString() != null) {
			urlBuffer.append("?").append(request.getQueryString());
		}
		final String requestUri = urlBuffer.toString();
		return this.ignoreUrlPatternMatcherStrategyClass.matches(requestUri);
	}
}
