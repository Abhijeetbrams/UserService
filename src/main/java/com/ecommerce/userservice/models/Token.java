package com.ecommerce.userservice.models;

import jakarta.persistence.ManyToMany;
import lombok.Getter;
import lombok.Setter;

import java.util.Date;

@Getter
@Setter
public class Token extends BaseModel{

    private String value;
    private Date expiryDate;

    @ManyToMany
    private User user;

}
