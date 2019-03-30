package com.hedian.platform.config;

import com.hedian.platform.bean.CasConfig;
import org.jasig.cas.client.session.SingleSignOutFilter;
import org.jasig.cas.client.session.SingleSignOutHttpSessionListener;
import org.jasig.cas.client.util.HttpServletRequestWrapperFilter;
import org.jasig.cas.client.validation.Cas30ProxyReceivingTicketValidationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.web.servlet.ServletListenerRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.HashMap;
import java.util.Map;

/**
 * @ClassName: ServerConfig
 * @Description: server配置
 * @Auther: SuperWang
 * @Date: 2019/3/28 14:34
 * @Vsersion: 0.0.1
 */
@Configuration
public class ServerConfig {
	@Autowired
	CasConfig casConfig;
	@Bean
	public ServletListenerRegistrationBean singleSignOutListenerRegistration(){
		ServletListenerRegistrationBean registrationBean = new ServletListenerRegistrationBean();
		registrationBean.setListener(new SingleSignOutHttpSessionListener());
		registrationBean.setOrder(1);
		return registrationBean;
	}

	@Bean
	public FilterRegistrationBean filterSingleRegistration() {
		FilterRegistrationBean registration = new FilterRegistrationBean();
		registration.setFilter(new SingleSignOutFilter());
		// 设定匹配的路径
		registration.addUrlPatterns("/*");
		Map<String,String> initParameters = new HashMap<String, String>();
		initParameters.put("casServerUrlPrefix", casConfig.getServerUrlPrefix());
		registration.setInitParameters(initParameters);
		// 设定加载的顺序
		registration.setOrder(1);
		return registration;
	}
	/**
	 * 授权过滤器
	 * @return
	 */
	@Bean
	public FilterRegistrationBean filterAuthenticationRegistration() {
		FilterRegistrationBean registration = new FilterRegistrationBean();
		registration.setFilter(new AuthenticationFilterWeb());
		// 设定匹配的路径
		registration.addUrlPatterns("/*");
		Map<String,String>  initParameters = new HashMap<String, String>();
		initParameters.put("casServerLoginUrl", casConfig.getServerLoginUrl());
		initParameters.put("serverName", casConfig.getClientHostUrl());

		registration.setInitParameters(initParameters);
		// 设定加载的顺序
		registration.setOrder(2);
		return registration;
	}
	/**
	 * 过滤验证器
	 * @return
	 */
	@Bean
	public FilterRegistrationBean filterValidationRegistration() {
		FilterRegistrationBean registration = new FilterRegistrationBean();
		registration.setFilter(new Cas30ProxyReceivingTicketValidationFilter());
		// 设定匹配的路径
		registration.addUrlPatterns("/*");
		Map<String,String>  initParameters = new HashMap<String, String>();
		initParameters.put("casServerUrlPrefix", casConfig.getServerUrlPrefix());
		initParameters.put("serverName", casConfig.getClientHostUrl());
		initParameters.put("useSession", "true");
		initParameters.put("redirectAfterValidation", "true");
		initParameters.put("authn_method", "mfa-duo");
		registration.setInitParameters(initParameters);
		// 设定加载的顺序
		registration.setOrder(3);
		return registration;
	}

	/**
	 * wraper过滤器
	 * @return
	 */
	@Bean
	public FilterRegistrationBean filterWrapperRegistration() {
		FilterRegistrationBean registration = new FilterRegistrationBean();
		registration.setFilter(new HttpServletRequestWrapperFilter());
		// 设定匹配的路径
		registration.addUrlPatterns("/*");
		// 设定加载的顺序
		registration.setOrder(1);
		return registration;
	}
}
