package com.videostream.authenticationservice;

import com.videostream.authenticationservice.Auth.AuthController;
import com.videostream.authenticationservice.Auth.AuthenticationRequest;
import com.videostream.authenticationservice.Auth.Validation.UserValidator;
import com.videostream.authenticationservice.JWT.JwtService;
import com.videostream.authenticationservice.JWT.JwtTokenPair;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class AuthControllerTest {

    @Autowired
    private AuthController controller;

    @Autowired
    JwtService service;


    private static String refreshToken;


    private final String mockUsername = "andrew";
    private final String mockPassword = "12Hello$%$!";

    private  boolean validateTokens(String jwtAccessToken, String jwtRefreshToken){
        return service.validAuthToken(jwtAccessToken) && service.validRefreshToken(jwtRefreshToken);
    }
    @Test
    @Order(1)
    void contextLoads() throws Exception{
        assertThat(controller).isNotNull();
        assertThat(service).isNotNull();
    }
    @Test
    @Order(2)
    void createAccount() throws Exception{
        ResponseEntity<?> responseEntity =  controller.createAccount(new UserValidator(mockUsername,mockPassword));
        assertThat(responseEntity.getStatusCode()).isSameAs(HttpStatus.CREATED);
        JwtTokenPair pair = (JwtTokenPair) responseEntity.getBody();
        assertThat(pair).isNotNull();
        boolean val = validateTokens(pair.accessToken(),pair.refreshToken());
        assertThat(val).isSameAs(true);
        refreshToken = pair.refreshToken();
    }
    //has to run after createAccount Test
    @Test
    @Order(4)
    void loginTest(){
        ResponseEntity<?> responseEntity = controller.authenticateUserSignOn(new AuthenticationRequest(mockUsername,mockPassword));
        assertThat(responseEntity.getStatusCode()).isSameAs(HttpStatus.OK);
        JwtTokenPair pair = (JwtTokenPair) responseEntity.getBody();
        assertThat(pair).isNotNull();
        boolean val = validateTokens(pair.accessToken(),pair.refreshToken());
        assertThat(val).isSameAs(true);
    }

    @Test
    @Order(3)
    void refreshAuth(){
        assertThat(refreshToken).isNotNull();
        ResponseEntity<?> responseEntity = controller.refreshAuthentication(Map.of("refreshToken",refreshToken));
        assertThat(responseEntity.getStatusCode()).isSameAs(HttpStatus.CREATED);
        JwtTokenPair pair = (JwtTokenPair) responseEntity.getBody();
        assertThat(pair).isNotNull();
        boolean val = validateTokens(pair.accessToken(),pair.refreshToken());
        assertThat(val).isSameAs(true);
    }

}
