package com.example;

import java.util.Map;

import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;

public class AzureUserInfoTokenServices extends UserInfoTokenServices {

	public AzureUserInfoTokenServices(String userInfoEndpointUrl, String clientId) {
		super(userInfoEndpointUrl, clientId);
	}

	@Override
	protected Object getPrincipal(Map<String, Object> map) {
		return super.getPrincipal(map);
	}
}