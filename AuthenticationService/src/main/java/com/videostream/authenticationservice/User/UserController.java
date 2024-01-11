package com.videostream.authenticationservice.User;

import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/auth/users/")
@Slf4j
@AllArgsConstructor
public class UserController {
    private final UserServices userServices;

    @PatchMapping
    public ResponseEntity<?> changePassword(@RequestBody @Valid ChangePasswordRequest request, Principal principal){
        userServices.changePassword(request,principal);
        return ResponseEntity.ok().body(Map.of("Password","Changed"));
    }
    @ExceptionHandler(MethodArgumentNotValidException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Map<String, String> invalidChangeRequest(MethodArgumentNotValidException ex){
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach((er)->{
            String fieldName = ((FieldError)er).getField();
            String message = er.getDefaultMessage();
            errors.put(fieldName,message);
        });
        return errors;
    }
    @ExceptionHandler(IllegalArgumentException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Map<String,String> invalidChangeRequest(IllegalArgumentException ex){
        return Map.of("Error",ex.getMessage());
    }
}
