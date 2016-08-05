package com.example;

import javax.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeAccessTokenProvider;
import org.springframework.stereotype.Component;

//@Component
//public class AzureRequestEnhancerCustomizer {
//
//    @Autowired
//    private OAuth2RestTemplate userInfoRestTemplate;
//
//    @PostConstruct
//    public void testWiring() {
//        AuthorizationCodeAccessTokenProvider authorizationCodeAccessTokenProvider = new AuthorizationCodeAccessTokenProvider();
//        authorizationCodeAccessTokenProvider.setTokenRequestEnhancer(new AzureRequestEnhancer());
//        userInfoRestTemplate.setAccessTokenProvider(authorizationCodeAccessTokenProvider);
//    }
//}
