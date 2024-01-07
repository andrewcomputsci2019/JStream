package com.videostream.authenticationservice.Auth;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.videostream.authenticationservice.Auth.Validation.UserValidator;
import com.videostream.authenticationservice.JWT.JwtService;
import com.videostream.authenticationservice.SecurityDetails.UserRepository;
import com.videostream.authenticationservice.User.UserBuilder;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private JwtService jwtService;
    private PasswordEncoder encoder;

    private UserRepository userRepository;
    @Autowired
    public AuthController(JwtService jwtService, PasswordEncoder encoder, UserRepository userRepository){
        this.jwtService = jwtService;
        this.encoder = encoder;
        this.userRepository = userRepository;
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
    @PostMapping(value = "/createAccount", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> createAccount(@Valid @RequestBody UserValidator validator){
        //should create the account the username does not exist and, b return a jwt RT and AT pair
        if(!userRepository.existsByUserName(validator.getUserName())){
            UserBuilder userBuilder = new UserBuilder();
            userBuilder.setUserName(validator.getUserName()).setPasswordHash(encoder.encode(validator.getPassword()));
            userRepository.save(userBuilder.createUser());
            //todo change this to a json response of the jwt
            return new ResponseEntity<>("Account Created",HttpStatus.CREATED);
        }
        return ResponseEntity.badRequest().body(Map.of("Creation Error","Username is already in use"));
    }
    @ExceptionHandler(MethodArgumentNotValidException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Map<String, String> invalidUserAccount(MethodArgumentNotValidException ex){
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach((er)->{
            String fieldName = ((FieldError)er).getField();
            String message = er.getDefaultMessage();
            errors.put(fieldName,message);
        });
        return errors;
    }
}
