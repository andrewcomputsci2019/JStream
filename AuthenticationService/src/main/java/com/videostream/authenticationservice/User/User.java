package com.videostream.authenticationservice.User;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

@Entity
@Table(name = "_users")
public class User implements UserDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    long id;
    String userName;
    @Setter
    String passwordHash;
    boolean enable;
    @Getter
    @Enumerated(EnumType.STRING)
    UserRoles roles;
    private final boolean accountNonExpired;
    private final boolean accountNonLocked;
    private final boolean credentialsNonExpired;


    public User(long id, String userName, String passwordHash, boolean enable, UserRoles roles, boolean accountNonExpired, boolean accountNonLocked, boolean credentialsNonExpired) {
        this.id = id;
        this.userName = userName;
        this.passwordHash = passwordHash;
        this.enable = enable;
        this.roles = roles;
        this.accountNonExpired = accountNonExpired;
        this.accountNonLocked = accountNonLocked;
        this.credentialsNonExpired = credentialsNonExpired;
    }
    public User(boolean accountNonExpired, boolean accountNonLocked, boolean credentialsNonExpired) {
        this.accountNonExpired = accountNonExpired;
        this.accountNonLocked = accountNonLocked;
        this.credentialsNonExpired = credentialsNonExpired;
    }

    public User() {
        this(true,true, true);
    }


    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return roles.grantedAuthority();
    }

    @Override
    public String getPassword() {
        return passwordHash;
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
        return enable;
    }

}
