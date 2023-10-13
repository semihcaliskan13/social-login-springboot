package com.example.simplesociallogin.enums;

import lombok.Getter;

@Getter
public enum Oauth2Role {
    USER("USER"), ADMIN("ADMIN");

    //to override enum's name.
    private String value;

    Oauth2Role(String value) {
        this.value = value;
    }
}
