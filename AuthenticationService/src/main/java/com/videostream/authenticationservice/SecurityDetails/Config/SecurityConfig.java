package com.videostream.authenticationservice.SecurityDetails.Config;

import com.videostream.authenticationservice.SecurityDetails.Filter.JwtAuthenticationEntryPoint;
import com.videostream.authenticationservice.SecurityDetails.Filter.JwtTokenFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

/**
 * Config configurer for authentication server
 */
@EnableWebSecurity
@Configuration
public class SecurityConfig {

    @Bean
    @Profile("dev")
    @Autowired
    public SecurityFilterChain securityFilterChain(
            HttpSecurity security,
            HandlerMappingIntrospector introspection,
            AuthenticationProvider provider,
            JwtTokenFilter filter,
            JwtAuthenticationEntryPoint entryPoint
    ) throws Exception {
        MvcRequestMatcher.Builder mvcMatcherBuilder = new MvcRequestMatcher.Builder(introspection);
        security.csrf((AbstractHttpConfigurer::disable));
        security.cors(AbstractHttpConfigurer::disable); //production change to stricter policy
        security.authorizeHttpRequests(authorizationManagerRequestMatcherRegistry -> authorizationManagerRequestMatcherRegistry
                .requestMatchers(mvcMatcherBuilder.pattern("/auth/*")).permitAll()
                .requestMatchers(PathRequest.toH2Console()).permitAll()
                .requestMatchers(mvcMatcherBuilder.pattern("/auth/users/")).authenticated());
        security.sessionManagement(httpSecuritySessionManagementConfigurer ->
                httpSecuritySessionManagementConfigurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        security.headers(httpSecurityHeadersConfigurer ->
                httpSecurityHeadersConfigurer.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable)
        );
        security.exceptionHandling(
                httpSecurityExceptionHandlingConfigurer ->
                        httpSecurityExceptionHandlingConfigurer.authenticationEntryPoint(entryPoint));
        security.authenticationProvider(provider).addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class);
        return security.build();
    }
}
