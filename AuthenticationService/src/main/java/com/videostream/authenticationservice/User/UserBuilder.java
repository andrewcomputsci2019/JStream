package com.videostream.authenticationservice.User;

public class UserBuilder {
    private long id;
    private String userName;
    private String passwordHash;
    private boolean enable = true;
    private UserRoles roles = UserRoles.USER;
    private boolean accountNonExpired = true;
    private boolean accountNonLocked = true;
    private boolean credentialsNonExpired = true;

    public UserBuilder setId(long id) {
        this.id = id;
        return this;
    }

    public UserBuilder setUserName(String userName) {
        this.userName = userName;
        return this;
    }

    public UserBuilder setPasswordHash(String passwordHash) {
        this.passwordHash = passwordHash;
        return this;
    }

    public UserBuilder setEnable(boolean enable) {
        this.enable = enable;
        return this;
    }

    public UserBuilder setRoles(UserRoles roles) {
        this.roles = roles;
        return this;
    }

    public UserBuilder setAccountNonExpired(boolean accountNonExpired) {
        this.accountNonExpired = accountNonExpired;
        return this;
    }

    public UserBuilder setAccountNonLocked(boolean accountNonLocked) {
        this.accountNonLocked = accountNonLocked;
        return this;
    }

    public UserBuilder setCredentialsNonExpired(boolean credentialsNonExpired) {
        this.credentialsNonExpired = credentialsNonExpired;
        return this;
    }

    public User createUser() {
        return new User(id, userName, passwordHash, enable, roles, accountNonExpired, accountNonLocked, credentialsNonExpired);
    }
}