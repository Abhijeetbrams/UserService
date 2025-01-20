package com.ecommerce.userservice.services;

import com.ecommerce.userservice.DTOs.LoginRequestDTO;
import com.ecommerce.userservice.DTOs.SignUpRequestDTO;
import com.ecommerce.userservice.DTOs.UserDTO;
import com.ecommerce.userservice.models.Token;
import com.ecommerce.userservice.models.User;

public interface UserService {
    User signUp(SignUpRequestDTO signUpRequestDTO);
    Token login(LoginRequestDTO loginRequestDTO);
    UserDTO getUser(String username);
    User logout(String tokenValue);
    User validate(String tokenValue);
}
