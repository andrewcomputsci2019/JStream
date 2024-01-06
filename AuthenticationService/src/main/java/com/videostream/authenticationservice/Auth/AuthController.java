package com.videostream.authenticationservice.Auth;

import com.videostream.authenticationservice.JWT.JwtService;
import org.springframework.beans.factory.annotation.Autowired;
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
    @GetMapping("/pubkey")
    public ResponseEntity<?> getPublicKey(){
        return ResponseEntity.ok(jwtService.getRSA_PublicKey());
    }
}
