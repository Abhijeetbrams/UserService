package com.ecommerce.userservice.controllers;

import com.ecommerce.userservice.DTOs.LoginRequestDTO;
import com.ecommerce.userservice.DTOs.LogoutRequestDTO;
import com.ecommerce.userservice.DTOs.SignUpRequestDTO;
import com.ecommerce.userservice.DTOs.UserDTO;
import com.ecommerce.userservice.exceptions.UserServiceException;
import com.ecommerce.userservice.models.Token;
import com.ecommerce.userservice.models.User;
import com.ecommerce.userservice.services.UserService;
import lombok.Getter;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@RestController
@RequestMapping("/users")
public class UserController {

    UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/signup")
    public ResponseEntity<UserDTO> signUp(@RequestBody SignUpRequestDTO signUpRequestDTO) {
        UserDTO userDTO = null;

        try{
            User user = userService.signUp(signUpRequestDTO);
            userDTO = UserDTO.from(user);
        }catch(Exception e){
            throw new UserServiceException("User already exists");
        }

        return new ResponseEntity<UserDTO>(userDTO, HttpStatus.CREATED);
    }

    @PostMapping("/login")
    public ResponseEntity<Token> login(@RequestBody LoginRequestDTO loginRequestDTO) {
        Token token = null;
        try{
            token = userService.login(loginRequestDTO);
        }catch(Exception e){
            throw new UserServiceException(e.getMessage());
        }

        return new ResponseEntity<Token>(token, HttpStatus.OK);
    }

    @GetMapping("/logout")
    public ResponseEntity<String> logout(@RequestParam String token) {
        try{
            userService.logout(token);
        }catch (Exception e){
            throw new UserServiceException(e.getMessage());
        }
        return new ResponseEntity<String>("User logged out successfully", HttpStatus.OK);

    }

    @GetMapping("/validate")
    public ResponseEntity<UserDTO> validate(@RequestParam String token) {
        User user = userService.validate(token);
        UserDTO userDTO = null;
        if(user==null){
            throw new UserServiceException("User not found");
        }
        userDTO = UserDTO.from(user);
        return new ResponseEntity<UserDTO>(userDTO, HttpStatus.OK);
    }
    // Some Random changes
}
