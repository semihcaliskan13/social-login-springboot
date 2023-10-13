package com.example.simplesociallogin.security.oauth2;

import com.example.simplesociallogin.enums.Oauth2Provider;
import com.example.simplesociallogin.enums.Oauth2Role;
import com.example.simplesociallogin.security.CustomUserDetails;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Service
public class GoogleOauth2UserInfoExtractor implements Oauth2UserInfoExtractor {
    @Override
    public CustomUserDetails extractUserInfo(OAuth2User oAuth2User) {
        CustomUserDetails customUserDetails = new CustomUserDetails();
        customUserDetails.setUsername(retrieveAttribute("email", oAuth2User));
        customUserDetails.setName(retrieveAttribute("name", oAuth2User));
        customUserDetails.setEmail(retrieveAttribute("email", oAuth2User));
        customUserDetails.setAvatarUrl(retrieveAttribute("picture", oAuth2User));
        customUserDetails.setProvider(Oauth2Provider.GOOGLE);
        customUserDetails.setAttributes(oAuth2User.getAttributes());
        customUserDetails.setAuthorities(Collections.singletonList(new SimpleGrantedAuthority(Oauth2Role.ADMIN.name())));
        return customUserDetails;
    }

    @Override
    public boolean accepts(OAuth2UserRequest userRequest) {
        return Oauth2Provider.GOOGLE.name().equalsIgnoreCase(userRequest.getClientRegistration().getRegistrationId());
    }

    private String retrieveAttribute(String attr, OAuth2User oAuth2User) {
        Object attribute = oAuth2User.getAttributes().get(attr);
        return attribute == null ? "" : attribute.toString();
    }
}
