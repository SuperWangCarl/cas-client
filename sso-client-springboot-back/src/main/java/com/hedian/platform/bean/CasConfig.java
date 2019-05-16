package com.hedian.platform.bean;

import lombok.Data;
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
@Data
@ConfigurationProperties(prefix = "cas")
public class CasConfig {
	private String serverUrlPrefix;
	private String serverLoginUrl;
	private String clientHostUrl;
	public static String clientWebUrl;

}
