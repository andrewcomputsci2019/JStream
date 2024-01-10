package com.videostream.authenticationservice.Auth;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.videostream.authenticationservice.Auth.Validation.UserValidator;
import com.videostream.authenticationservice.JWT.JwtService;
import com.videostream.authenticationservice.JWT.JwtTokenPair;
import com.videostream.authenticationservice.SecurityDetails.UserRepository;
import com.videostream.authenticationservice.User.User;
import com.videostream.authenticationservice.User.UserBuilder;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final JwtService jwtService;
    private final PasswordEncoder encoder;

    private final UserRepository userRepository;

    @Autowired
    public AuthController(JwtService jwtService, PasswordEncoder encoder, UserRepository userRepository) {
        this.jwtService = jwtService;
        this.encoder = encoder;
        this.userRepository = userRepository;
    }

    @PostMapping({"/login"})
    public ResponseEntity<?> authenticateUserSignOn(@RequestBody AuthenticationRequest request) {
        User userInDataBase = userRepository.findByUserName(request.username()).orElse(null);
        if (userInDataBase == null) {
            return ResponseEntity.badRequest().body(Map.of("Error", "Username not found"));
        }
        if (!encoder.matches(request.password(), userInDataBase.getPassword())) {
            return ResponseEntity.badRequest().body(Map.of("Error", "Password is incorrect"));
        }
        Map<String, Object> claims = new HashMap<>();
        claims.put("Role", userInDataBase.getRoles().name());
        return ResponseEntity.ok()
                .body(
                        new JwtTokenPair(jwtService.buildAccessToken(userInDataBase, claims), jwtService.buildRefreshToken(userInDataBase))
                );
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshAuthentication(@RequestBody Map<String, String> tokenMap) {
        String refreshToken = tokenMap.get("refreshToken");
        if (jwtService.validRefreshToken(refreshToken)) { // refresh token is valid
            String username = jwtService.getUserNameRefreshToken(refreshToken); // get username from payload (?)
            User currentAccount = userRepository.findByUserName(username).orElseThrow(() -> new UsernameNotFoundException("Account does not exist"));
            Map<String, Object> claims = new HashMap<>();
            claims.put("Role", currentAccount.getRoles().name());
            String newAccessToken = jwtService.buildAccessToken(currentAccount, claims);
            String newRefreshToken = jwtService.buildRefreshToken(currentAccount);
            jwtService.extractClaimsFromAuthToken(newAccessToken); // is this line necessary?
            return new ResponseEntity<>(new JwtTokenPair(newAccessToken, newRefreshToken), HttpStatus.CREATED);
        }
        return ResponseEntity.badRequest().body(Map.of("New auth and refresh token generation failed", "Refresh token invalid"));
    }

    @GetMapping(value = "/pubkey", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> getPublicKey() throws JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode root = mapper.createObjectNode();
        root.put("Key", jwtService.getRSA_PublicKey());
        return ResponseEntity.ok(mapper.writer().writeValueAsString(root));
    }

    @PostMapping(value = "/createAccount", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> createAccount(@Valid @RequestBody UserValidator validator) {
        if (!userRepository.existsByUserName(validator.getUserName())) {
            UserBuilder userBuilder = new UserBuilder();
            userBuilder.setUserName(validator.getUserName()).setPasswordHash(encoder.encode(validator.getPassword()));
            User user = userBuilder.createUser();
            userRepository.save(user);
            Map<String, Object> claims = new HashMap<>();
            claims.put("Role", user.getRoles().name());
            String accessToken = jwtService.buildAccessToken(user, claims);
            String refreshToken = jwtService.buildRefreshToken(user);
            jwtService.extractClaimsFromAuthToken(accessToken);
            return new ResponseEntity<>(new JwtTokenPair(accessToken, refreshToken), HttpStatus.CREATED);
        }
        return ResponseEntity.badRequest().body(Map.of("Creation Error", "Username is already in use"));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Map<String, String> invalidUserAccount(MethodArgumentNotValidException ex) {
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach((er) -> {
            String fieldName = ((FieldError) er).getField();
            String message = er.getDefaultMessage();
            errors.put(fieldName, message);
        });
        return errors;
    }
}
