package com.videostream.authenticationservice.User;

import com.videostream.authenticationservice.JWT.JwtUser;
import com.videostream.authenticationservice.SecurityDetails.UserRepository;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.Principal;

@Service
@AllArgsConstructor
public class UserServices {

    private final PasswordEncoder encoder;
    private final UserRepository repository;

    public void changePassword(ChangePasswordRequest request, Principal principal){
        User existingAccount =  repository.findByUserName(
                ((JwtUser)((UsernamePasswordAuthenticationToken)principal).getPrincipal()).getUsername()
        ).orElseThrow(()-> new UsernameNotFoundException("Account does not exist"));
        if(!encoder.matches(request.getOldPassword(), existingAccount.getPassword())){
            throw new IllegalArgumentException("Old Password does not match existing password");
        }
        if(request.getOldPassword().equals(request.getNewPassword())){
            throw new IllegalArgumentException("New passwords can be the same as the old password");
        }
        existingAccount.setPasswordHash(encoder.encode(request.getNewPassword()));
        repository.save(existingAccount);
    }
}
