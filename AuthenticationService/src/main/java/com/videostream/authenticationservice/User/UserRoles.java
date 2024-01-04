package com.videostream.authenticationservice.User;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Set;

public enum UserRoles{
    ADMIN,
    USER;
    public Set<SimpleGrantedAuthority> grantedAuthority(){
        return Set.of(new SimpleGrantedAuthority("ROLE_"+this.name()));
    }
}
