package com.videostream.authenticationservice.SecurityDetails;

import com.videostream.authenticationservice.User.User;
import org.springframework.data.jpa.repository.JpaRepository;



import java.util.Optional;

public interface UserRepository extends JpaRepository<User,Integer> {

    default Optional<User> findByUserName(String userName) {
        return Optional.empty();
    }
}
