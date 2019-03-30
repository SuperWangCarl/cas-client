package com.hedian.platform.bean;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * @ClassName: CasConfig
 * @Description: cas配置
 * @Auther: SuperWang
 * @Date: 2019/3/28 14:29
 * @Vsersion: 0.0.1
 */
@Component
@ConfigurationProperties(prefix = "cas")
public class CasConfig {
	private String serverUrlPrefix;
	private String serverLoginUrl;
	private String clientHostUrl;
	public static String clientWebUrl;

	public String getServerUrlPrefix() {
		return serverUrlPrefix;
	}

	public void setServerUrlPrefix(String serverUrlPrefix) {
		this.serverUrlPrefix = serverUrlPrefix;
	}

	public String getServerLoginUrl() {
		return serverLoginUrl;
	}

	public void setServerLoginUrl(String serverLoginUrl) {
		this.serverLoginUrl = serverLoginUrl;
	}

	public String getClientHostUrl() {
		return clientHostUrl;
	}

	public void setClientHostUrl(String clientHostUrl) {
		this.clientHostUrl = clientHostUrl;
	}

	public String getClientWebUrl() {
		return clientWebUrl;
	}

	public void setClientWebUrl(String clientWebUrl) {
		this.clientWebUrl = clientWebUrl;
	}
}
