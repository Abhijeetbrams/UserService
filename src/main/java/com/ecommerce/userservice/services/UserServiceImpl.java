package com.ecommerce.userservice.services;

import com.ecommerce.userservice.DTOs.LoginRequestDTO;
import com.ecommerce.userservice.DTOs.SignUpRequestDTO;
import com.ecommerce.userservice.DTOs.UserDTO;
import com.ecommerce.userservice.models.Token;
import com.ecommerce.userservice.models.User;
import com.ecommerce.userservice.repository.TokenRepository;
import com.ecommerce.userservice.repository.UserRepository;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Calendar;
import java.util.Date;
import java.util.Optional;

@Service
public class UserServiceImpl implements UserService {

    private UserRepository userRepository;
    // private final RoleRepository roleRepository;
     private TokenRepository tokenRepository;
     private BCryptPasswordEncoder passwordEncoder;

    public UserServiceImpl(UserRepository userRepository,BCryptPasswordEncoder passwordEncoder, TokenRepository tokenRepository) {
        this.userRepository = userRepository;
        // this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.tokenRepository=tokenRepository;
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
        user.setPassword(passwordEncoder.encode(signUpRequestDTO.getPassword()));
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
        if (!passwordEncoder.matches(loginRequestDTO.getPassword(),user.getPassword())) {
            throw new RuntimeException("Invalid password");
        }

        Token token = new Token();
        token.setUser(user);

        // Setting Random Token Value
        token.setValue(RandomStringUtils.randomAlphanumeric(128));

        Date currentDate = new Date();
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(currentDate);

        calendar.add(Calendar.DAY_OF_MONTH, 30);
        token.setExpiryDate(calendar.getTime());

        // saving the token in the database
        tokenRepository.save(token);
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
    public void logout(String tokenValue){
        Optional<Token> token = tokenRepository.findByValue(tokenValue);
        if(!token.isPresent()){
            new RuntimeException("Token not found");
        }
        Token token1=token.get();
        token1.setIsDeleted(true);
        tokenRepository.save(token1);
    }

    @Override
    public User validate(String tokenValue) {
        // Check if the Token is present in the database, token is not deleted and token is not expired
        // token's expiry time is greater than the current time.
        Optional<Token> optionalToken = tokenRepository.findByValueAndIsDeletedAndExpiryDateGreaterThan(tokenValue, false, new Date());

        return optionalToken.map(Token::getUser).orElse(null);
    }
}