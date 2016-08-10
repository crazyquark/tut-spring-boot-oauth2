/*
 * Copyright 2012-2015 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.example;

import java.io.IOException;
import java.net.URI;
import java.security.Principal;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.Filter;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.context.embedded.FilterRegistrationBean;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.http.ResponseEntity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.AccessTokenProvider;
import org.springframework.security.oauth2.client.token.AccessTokenProviderChain;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsAccessTokenProvider;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@SuppressWarnings("deprecation")
@SpringBootApplication
@EnableOAuth2Client
@RestController
public class SocialApplication extends WebSecurityConfigurerAdapter {

  @Autowired
  OAuth2ClientContext oauth2ClientContext;

  @RequestMapping("/user")
  public Principal user(Principal principal) {
    return principal;
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http.antMatcher("/**").authorizeRequests().antMatchers("/", "/login**", "/webjars/**").permitAll().anyRequest()
        .authenticated()
        .and().logout().logoutSuccessUrl("/").permitAll()
        .and().addFilterBefore(ssoFilter(), BasicAuthenticationFilter.class);

    http.csrf().disable();
  }

  private Filter ssoFilter() {
    OAuth2ClientAuthenticationProcessingFilter facebookFilter = new OAuth2ClientAuthenticationProcessingFilter(
        "/login");
    OAuth2RestTemplate facebookTemplate = new OAuth2RestTemplate(azureClient(), oauth2ClientContext);
    facebookTemplate.setAccessTokenProvider(accessTokenProvider());

    facebookFilter.setRestTemplate(facebookTemplate);

    facebookFilter
        .setTokenServices(new UserInfoTokenServices(azureResource().getUserInfoUri(), azureClient().getClientId()));
    return facebookFilter;
  }

  @Bean(name = "accessTokenProvider")
  public AccessTokenProvider accessTokenProvider() {

    AzureIdTokenProvider authorizationCodeAccessTokenProvider = new AzureIdTokenProvider();
    authorizationCodeAccessTokenProvider.setTokenRequestEnhancer(new AzureRequestEnhancer());

    // return authorizationCodeAccessTokenProvider;
    /*
     * ImplicitAccessTokenProvider implicitAccessTokenProvider = new
     * ImplicitAccessTokenProvider(); ResourceOwnerPasswordAccessTokenProvider
     * resourceOwnerPasswordAccessTokenProvider = new
     * ResourceOwnerPasswordAccessTokenProvider();
     */
    ClientCredentialsAccessTokenProvider clientCredentialsAccessTokenProvider = new ClientCredentialsAccessTokenProvider();

    return new AccessTokenProviderChain(Arrays.<AccessTokenProvider> asList(authorizationCodeAccessTokenProvider,
        clientCredentialsAccessTokenProvider));

    /*
     * return new AccessTokenProviderChain(Arrays.<AccessTokenProvider>asList(
     * authorizationCodeAccessTokenProvider, implicitAccessTokenProvider,
     * resourceOwnerPasswordAccessTokenProvider,
     * clientCredentialsAccessTokenProvider));
     * 
     */
  }

  @Bean
  @ConfigurationProperties("azure.resource")
  ResourceServerProperties azureResource() {
    ResourceServerProperties res = new ResourceServerProperties();

    return res;
  }

  @Bean
  @ConfigurationProperties("azure.client")
  AzureResourceDetails azureClient() {
    AzureResourceDetails res = new AzureResourceDetails();
    return res;
  }

  @Bean
  public FilterRegistrationBean oauth2ClientFilterRegistration(OAuth2ClientContextFilter filter) {
    FilterRegistrationBean registration = new FilterRegistrationBean();
    registration.setFilter(filter);
    registration.setOrder(-100);
    return registration;
  }

  public static void main(String[] args) {
    SpringApplication.run(SocialApplication.class, args);
  }
}
