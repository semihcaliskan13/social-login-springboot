package com.example.simplesociallogin.security.oauth2;

import com.example.simplesociallogin.entity.User;
import com.example.simplesociallogin.enums.Oauth2Role;
import com.example.simplesociallogin.security.CustomUserDetails;
import com.example.simplesociallogin.service.UserService;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;

@Component
public class CustomOauth2UserService extends DefaultOAuth2UserService {

    private final UserService userService;
    private final List<Oauth2UserInfoExtractor> oauth2UserInfoExtractors;

    public CustomOauth2UserService(UserService userService, List<Oauth2UserInfoExtractor> oauth2UserInfoExtractors) {
        this.userService = userService;
        this.oauth2UserInfoExtractors = oauth2UserInfoExtractors;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);
        Optional<Oauth2UserInfoExtractor> extractor = oauth2UserInfoExtractors
                .stream()
                .filter(oauth2UserInfoExtractor -> oauth2UserInfoExtractor.accepts(userRequest))
                .findFirst();
        if (extractor.isEmpty()){
            throw new InternalAuthenticationServiceException("The OAuth2 provider not supported yet.");
        }
        CustomUserDetails userDetails = extractor.get().extractUserInfo(oAuth2User);
        User user = upsertUser(userDetails);
        userDetails.setId(user.getId());
        return userDetails;
    }

    private User upsertUser(CustomUserDetails customUserDetails) {
        Optional<User> userOptional = userService.getUserByUsername(customUserDetails.getUsername());
        User user;
        if (userOptional.isEmpty()) {
            user = new User();
            user.setUsername(customUserDetails.getUsername());
            user.setName(customUserDetails.getName());
            user.setEmail(customUserDetails.getEmail());
            user.setImageUrl(customUserDetails.getAvatarUrl());
            user.setProvider(customUserDetails.getProvider());
            user.setRole(Oauth2Role.USER.getValue());
        } else {
            user = userOptional.get();
            user.setEmail(customUserDetails.getEmail());
            user.setImageUrl(customUserDetails.getAvatarUrl());
        }
        return userService.saveUser(user);


    }
}
