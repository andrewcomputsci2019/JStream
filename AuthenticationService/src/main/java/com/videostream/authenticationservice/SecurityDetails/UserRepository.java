package com.videostream.authenticationservice.SecurityDetails;

import com.videostream.authenticationservice.User.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.lang.NonNull;


import java.util.Optional;

public interface UserRepository extends JpaRepository<User,Integer> {

     Optional<User> findByUserName(String userName);

    boolean existsByUserName(@NonNull String userName);

}
