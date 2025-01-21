package com.ecommerce.userservice.repository;

import com.ecommerce.userservice.models.Token;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Date;
import java.util.Optional;

@Repository
public interface TokenRepository extends JpaRepository<Token, Long> {
    Optional<Token> findByValue(String value);

    Optional<Token> findByValueAndIsDeletedAndExpiryDateGreaterThan(String tokenValue, boolean isDeleted, Date currentTime);
}
