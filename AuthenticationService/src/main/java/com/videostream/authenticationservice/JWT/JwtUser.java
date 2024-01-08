package com.videostream.authenticationservice.JWT;

import com.videostream.authenticationservice.User.UserRoles;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

/**
 * Facade user, for signing in using JWT, no mention of user password
 */
@NoArgsConstructor
public class JwtUser implements UserDetails {
    private String userName;
    UserRoles roles;

    public JwtUser(String userName, UserRoles roles) {
        this.userName = userName;
        this.roles = roles;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return roles.grantedAuthority();
    }

    @Override
    public String getPassword() {
        return null;
    }

    @Override
    public String getUsername() {
        return userName;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

}
