package com.ecommerce.userservice.services;

import com.ecommerce.userservice.DTOs.LoginRequestDTO;
import com.ecommerce.userservice.DTOs.SendEmailDTO;
import com.ecommerce.userservice.DTOs.SignUpRequestDTO;
import com.ecommerce.userservice.DTOs.UserDTO;
import com.ecommerce.userservice.configuration.KafkaProducerClient;
import com.ecommerce.userservice.models.Token;
import com.ecommerce.userservice.models.User;
import com.ecommerce.userservice.repository.TokenRepository;
import com.ecommerce.userservice.repository.UserRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.kafka.clients.producer.KafkaProducer;
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
     //Step 3:- Injecting the KafkaProducerClient bean in the UserServiceImpl after adding dependency of Spring Kafka in the pom.xml
     private KafkaProducerClient kafkaProducerClient;
     private ObjectMapper objectMapper;

    public UserServiceImpl(UserRepository userRepository,BCryptPasswordEncoder passwordEncoder,
                           TokenRepository tokenRepository, KafkaProducerClient kafkaProducerClient,
                           ObjectMapper objectMapper) {
        this.userRepository = userRepository;
        // this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.tokenRepository=tokenRepository;
        this.kafkaProducerClient = kafkaProducerClient;
        this.objectMapper=objectMapper;
    }

    @Override
    public User signUp(SignUpRequestDTO signUpRequestDTO) {
        // Check First Email Id Already registered or not
        Optional<User> optionalUser = userRepository.findByEmail(signUpRequestDTO.getEmail());
        if (optionalUser.isPresent()) {
            throw new RuntimeException("User already exists");
        }
        User user = new User();
        user.setUsername(signUpRequestDTO.getUsername());
        user.setEmail(signUpRequestDTO.getEmail());
        user.setPassword(passwordEncoder.encode(signUpRequestDTO.getPassword()));
        //Role role = roleRepository.findByValue("USER");
        // user.setRole(role);
        user= userRepository.save(user);

        // Step 3:- Sending the message to the Kafka topic, here our use-case is after saving the user in the database, we are sending the user email to the Kafka topic.
        SendEmailDTO sendEmailDTO = new SendEmailDTO();
        sendEmailDTO.setRecipient(user.getEmail());
        sendEmailDTO.setSender("abybrams@gmail.com");
        sendEmailDTO.setSubject("Welcome to Ecommerce");
        sendEmailDTO.setBody("Welcome to Ecommerce, you have successfully registered with us.");

        // Step 4:- Here we need to send the message to Topic named SendEmail and Json message is sendEmailDTO.
        // However sendEmailDTO is a DTO or a class object we need to convert it to JSON format using Jackson Library.
        String message="";
        try {
            message=objectMapper.writeValueAsString(sendEmailDTO);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
        kafkaProducerClient.sendMessage("SendEmail",message);

        return user;
    }

    @Override
    public Token login(LoginRequestDTO loginRequestDTO) {
        Optional<User> optionalUser = userRepository.findByEmail(loginRequestDTO.getEmail());
        if (optionalUser.isEmpty()) {
            throw new RuntimeException("User not found");
        }
        if (!passwordEncoder.matches(loginRequestDTO.getPassword(),optionalUser.get().getPassword())) {
            throw new RuntimeException("Invalid password");
        }

        Token token = new Token();
        token.setUser(optionalUser.get());

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
        Optional<User> user = userRepository.findByEmail(email);
        UserDTO userDTO = new UserDTO();
        userDTO.setUsername(user.get().getUsername());
        userDTO.setEmail(user.get().getEmail());
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