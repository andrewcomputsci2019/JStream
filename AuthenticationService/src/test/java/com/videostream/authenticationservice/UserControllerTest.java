package com.videostream.authenticationservice;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.videostream.authenticationservice.Auth.AuthenticationRequest;
import com.videostream.authenticationservice.SecurityDetails.UserRepository;
import com.videostream.authenticationservice.User.ChangePasswordRequest;
import com.videostream.authenticationservice.User.User;
import com.videostream.authenticationservice.User.UserBuilder;
import com.videostream.authenticationservice.User.UserRoles;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;


import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class UserControllerTest {


    private static final String USERNAME = "andrew";
    private static final String PASSWORD = "HelloWorld12~!";
    private static final String NEW_PASSWORD = "ChangedPassword~!123";

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    UserRepository repository;
    @Autowired
    PasswordEncoder encoder;


    public void CreateUserAccount() {
        User user = new UserBuilder().setUserName(USERNAME).setPasswordHash(encoder.encode(PASSWORD)).setRoles(UserRoles.USER)
                .createUser();
        repository.save(user);
    }

    @Test
    @Order(1)
    public void onContextLoad() {
        assertThat(mockMvc).isNotNull();
        assertThat(repository).isNotNull();
        assertThat(encoder).isNotNull();
        CreateUserAccount();
    }

    @Test
    @Order(2)
    public void changePasswordTest() throws Exception {

        String jsonRequest = new ObjectMapper().writeValueAsString(new AuthenticationRequest(USERNAME,PASSWORD));
        String json = mockMvc
                .perform(
                        MockMvcRequestBuilders
                                .post("/auth/login").contentType(MediaType.APPLICATION_JSON)
                                .content(jsonRequest)
                )
                .andDo(
                        print()
                )
                .andExpect(
                        status().isOk()
                )
                .andReturn()
                .getResponse()
                .getContentAsString();
        JsonNode root = new ObjectMapper().readTree(json);
        String accessToken = root.get("accessToken").asText();
        jsonRequest = new ObjectMapper().writeValueAsString(new ChangePasswordRequest(PASSWORD,NEW_PASSWORD));
        json = mockMvc
                .perform(
                        MockMvcRequestBuilders
                                .patch("/auth/users/")
                                .contentType(MediaType.APPLICATION_JSON)
                                .header("Authorization", "Bearer " + accessToken)
                                .content(jsonRequest)
                )
                .andExpect(
                        status().isOk()
                )
                .andExpect(
                        content()
                                .contentTypeCompatibleWith(MediaType.APPLICATION_JSON)
                ).andReturn()
                .getResponse()
                .getContentAsString();
        root = new ObjectMapper().readTree(json);
        assertThat(root.has("Password")).isTrue();
    }

}
