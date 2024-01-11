package com.videostream.authenticationservice;

import com.videostream.authenticationservice.Auth.AuthenticationRequest;
import com.videostream.authenticationservice.JWT.JwtService;
import com.videostream.authenticationservice.JWT.JwtTokenPair;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class AuthenticationServiceApplicationTests {

    private static final String TOKEN_PREFIX = "Bearer ";

    private static final String USER_NAME = "andrew";

    private static final String OLD_PASSWORD = "HelloWorld414#!";
    private static final String NEW_PASSWORD = "newPassword424!";

    private static String accessToken;
    private static String refreshToken;
    private static final String SERVER_PREFIX = "http://localhost:";

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    JwtService service;

    private  boolean validateTokens(String jwtAccessToken, String jwtRefreshToken){
        return service.validAuthToken(jwtAccessToken) && service.validRefreshToken(jwtRefreshToken);
    }

    @Test
    @Order(1)
    void contextLoads() {
        assertThat(restTemplate).isNotNull();
    }

    @Test
    @Order(2)
    void createAccountTest(){
        JwtTokenPair pair = restTemplate.postForObject(SERVER_PREFIX+port+"/auth/createAccount", Map.of("username",USER_NAME,"password",OLD_PASSWORD), JwtTokenPair.class);
        assertThat(pair).isNotNull();
        assertThat(validateTokens(pair.accessToken(),pair.refreshToken())).isTrue();
        accessToken = pair.accessToken();
        refreshToken = pair.refreshToken();
    }

    @Test
    @Order(3)
    void refreshTokenTest(){
        JwtTokenPair pair = restTemplate.postForObject(SERVER_PREFIX+port+"/auth/refresh",Map.of("refreshToken",refreshToken), JwtTokenPair.class);
        assertThat(pair).isNotNull();
        assertThat(validateTokens(pair.accessToken(),pair.refreshToken())).isTrue();
        accessToken = pair.accessToken();
        refreshToken = pair.refreshToken();
    }

    @Test
    @Order(4)
    void loginTest(){
        ResponseEntity<JwtTokenPair> entity = restTemplate.postForEntity(SERVER_PREFIX+port+"/auth/login",new AuthenticationRequest(USER_NAME,OLD_PASSWORD), JwtTokenPair.class);
        assertThat(entity.getStatusCode()).isSameAs(HttpStatus.OK);
        assertThat(entity.getBody()).isNotNull();
        JwtTokenPair pair = entity.getBody();
        assertThat(validateTokens(pair.accessToken(),pair.refreshToken())).isTrue();
        accessToken = pair.accessToken();
    }


}
