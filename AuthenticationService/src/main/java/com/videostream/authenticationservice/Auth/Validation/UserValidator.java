package com.videostream.authenticationservice.Auth.Validation;


import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public class UserValidator {

    @NotBlank(message = "Username can not be blank")
    @Size(min = 3, max = 25, message = "Username must be of at least size 3 and no longer than 25 characters")
    @JsonProperty("username")
    @JsonAlias("username")
    private String userName;
    @Pattern(regexp = "^(?=\\P{Ll}*\\p{Ll})(?=\\P{Lu}*\\p{Lu})(?=\\P{N}*\\p{N})(?=[\\p{L}\\p{N}]*[^\\p{L}\\p{N}])[\\s\\S]{10,20}$", message = "Password Not Valid")
    private String password;

    public String getUserName() {
        return userName;
    }

    public String getPassword() {
        return password;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public UserValidator(String userName, String password) {
        this.userName = userName;
        this.password = password;
    }
}
