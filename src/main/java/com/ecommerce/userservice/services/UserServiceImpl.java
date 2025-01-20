package com.ecommerce.userservice.services;

import com.ecommerce.userservice.DTOs.LoginRequestDTO;
import com.ecommerce.userservice.DTOs.SignUpRequestDTO;
import com.ecommerce.userservice.DTOs.UserDTO;
import com.ecommerce.userservice.models.Token;
import com.ecommerce.userservice.models.User;
import com.ecommerce.userservice.repository.UserRepository;
import org.springframework.stereotype.Service;

import java.util.Calendar;
import java.util.Date;
import java.util.Optional;

@Service
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;
    // private final RoleRepository roleRepository;
    // private final PasswordEncoder passwordEncoder;

    public UserServiceImpl(UserRepository userRepository) {
        this.userRepository = userRepository;
        // this.roleRepository = roleRepository;
        // this.passwordEncoder = passwordEncoder;
    }

    @Override
    public User signUp(SignUpRequestDTO signUpRequestDTO) {
        // Check First Email Id Already registered or not
        if (userRepository.findByEmail(signUpRequestDTO.getEmail()) != null) {
            throw new RuntimeException("User already exists");
        }
        User user = new User();
        user.setUsername(signUpRequestDTO.getUsername());
        user.setEmail(signUpRequestDTO.getEmail());
        user.setPassword(signUpRequestDTO.getPassword());
        //Role role = roleRepository.findByValue("USER");
        // user.setRole(role);
        return userRepository.save(user);
    }

    @Override
    public Token login(LoginRequestDTO loginRequestDTO) {
        User user = userRepository.findByEmail(loginRequestDTO.getEmail());
        if (user == null) {
            throw new RuntimeException("User not found");
        }
        if (!user.getPassword().equals(loginRequestDTO.getPassword())) {
            throw new RuntimeException("Invalid password");
        }

        Token token = new Token();
        token.setUser(user);

        Date currentDate = new Date();
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(currentDate);

        calendar.add(Calendar.DAY_OF_MONTH, 30);
        token.setExpiryDate(calendar.getTime());
        return token;
    }


    @Override
    public UserDTO getUser(String email) {
        User user = userRepository.findByEmail(email);
        UserDTO userDTO = new UserDTO();
        userDTO.setUsername(user.getUsername());
        userDTO.setEmail(user.getEmail());
        return userDTO;
    }

    @Override
    public User logout(String tokenValue){ return null;}

    @Override
    public User validate(String tokenValue){ return null;}
}