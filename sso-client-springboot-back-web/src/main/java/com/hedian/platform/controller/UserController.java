package com.hedian.platform.controller;


import com.hedian.platform.bean.CasConfig;
import org.jasig.cas.client.authentication.AttributePrincipal;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * <p>
 * 用户表 前端控制器
 * </p>
 *
 * @author SuperWang
 * @since 2019-03-13
 */
@RestController
@RequestMapping("/user")
public class UserController{
	@Autowired
	private CasConfig casConfig;

	/**
	 * Description: 用户登录验证 返回前端用户登录的token
	 */
	@GetMapping("/login")
	public void loginSSO(HttpServletResponse response) throws IOException {
		response.sendRedirect(casConfig.getClientWebUrl());
	}

	/**
	 * 获取token用于前后端校验
	 */
	@GetMapping("/gettoken")
	public Map<String, String> GetToken(HttpServletRequest  request) {
		HashMap<String, String> map = new HashMap<>();
		//获取登录的用户名
		String remoteUser = request.getRemoteUser();
		//取出登录的时间作为加密 密钥
		AttributePrincipal principal = (AttributePrincipal) request.getUserPrincipal();
		final Map attributes = principal.getAttributes();
		Object authenticationDate = attributes.get("authenticationDate");
		//使用登录的时间加密
		String dataTime = authenticationDate.toString();
		//给用户设置token
		map.put("token", "token加密后 自己实现");
		//向前端返回token
		return map;
	}



}

