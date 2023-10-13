package com.example.simplesociallogin.security.oauth2;

import com.example.simplesociallogin.security.CustomUserDetails;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.OAuth2User;

public interface Oauth2UserInfoExtractor {

    CustomUserDetails extractUserInfo(OAuth2User oAuth2User);
    boolean accepts(OAuth2UserRequest userRequest);
}
