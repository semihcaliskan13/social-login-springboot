package com.example.simplesociallogin.security;

import com.example.simplesociallogin.enums.Oauth2Provider;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.Map;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class CustomUserDetails implements OAuth2User, UserDetails {

    private Long id;
    private String username;
    private String password;
    private String name;
    private String email;
    private String avatarUrl;
    private Oauth2Provider provider;
    private Collection<? extends GrantedAuthority> authorities;
    private Map<String, Object> attributes;


    @Override
    public boolean isAccountNonExpired() {
        return false;
    }

    @Override
    public boolean isAccountNonLocked() {
        return false;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return false;
    }

    @Override
    public boolean isEnabled() {
        return false;
    }
}
