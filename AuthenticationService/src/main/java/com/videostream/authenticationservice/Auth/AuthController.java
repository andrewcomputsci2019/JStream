package com.videostream.authenticationservice.Auth;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.videostream.authenticationservice.JWT.JwtService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private JwtService jwtService;
    @Autowired
    public AuthController(JwtService jwtService){
        this.jwtService = jwtService;
    }
    @PostMapping({"/login"})
    public ResponseEntity<?> authenticateUserSignOn(@RequestBody AuthenticationRequest request){
        //todo validate user information is correct and return two tokens
        return null;
    }
    @PostMapping("/refresh")
    public ResponseEntity<?> refreshAuthentication(@RequestHeader("Authorization") String token){
        //todo validate token

        //todo return new refresh token and access token
        return null;
    }
    @GetMapping(value = "/pubkey",produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> getPublicKey() throws JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode root = mapper.createObjectNode();
        root.put("Key",jwtService.getRSA_PublicKey());
        return ResponseEntity.ok(mapper.writer().writeValueAsString(root));
    }
}
