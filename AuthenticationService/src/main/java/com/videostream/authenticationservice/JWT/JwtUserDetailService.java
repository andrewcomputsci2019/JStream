package com.videostream.authenticationservice.JWT;

import com.videostream.authenticationservice.User.UserRoles;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
@Slf4j
public class JwtUserDetailService implements UserDetailsService {


    private final JwtService jwtService;

    @Autowired
    public JwtUserDetailService(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    /**
     *
     * @param token the token that needs to be parsed, should be a valid auth token
     * @return a user details resolving user privileges
     * @throws UsernameNotFoundException if token is malformed
     */
    @Override
    public UserDetails loadUserByUsername(String token) throws UsernameNotFoundException {
        if(jwtService.getUserNameAuthToken(token) != null){
            //extract user Information like roles and username
            Map<String, String> map = jwtService.extractClaimsFromAuthToken(token);
            String user = map.get("sub");
            UserRoles roles = UserRoles.valueOf(map.get("Role"));
            return new JwtUser(user,roles);
        }
        throw new UsernameNotFoundException("Failed to get UserInformation from token");
    }
}
