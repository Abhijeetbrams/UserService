package com.ecommerce.userservice.DTOs;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class SendEmailDTO {
    // Creating this DTO to send the email, since in the email we have recipient,cc,bcc,subject and body.
    private String recipient;
    private String sender;
    private String subject;
    private String body;
}
