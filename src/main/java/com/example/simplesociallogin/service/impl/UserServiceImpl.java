package com.example.simplesociallogin.service.impl;

import com.example.simplesociallogin.entity.User;
import com.example.simplesociallogin.exception.UserNotFoundException.UserNotFoundException;
import com.example.simplesociallogin.repository.UserRepository;
import com.example.simplesociallogin.service.UserService;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class UserServiceImpl implements UserService {

    private final UserRepository repository;

    public UserServiceImpl(UserRepository repository) {
        this.repository = repository;
    }

    @Override
    public List<User> getUsers() {
        return repository.findAll();
    }

    @Override
    public Optional<User> getUserByUsername(String username) {
        return repository.findByUsername(username);
    }

    @Override
    public Optional<User> getUserByEmail(String email) {
        return repository.findByEmail(email);
    }

    @Override
    public boolean hasUserWithUsername(String username) {
        return repository.existsByUsername(username);
    }

    @Override
    public boolean hasUserWithEmail(String email) {
        return repository.existsByEmail(email);
    }

    @Override
    public User validateAndGetUserByUsername(String username) {
        return getUserByUsername(username)
                .orElseThrow(() -> new UserNotFoundException(String.format("User with username %s not found", username)));
    }

    @Override
    public User saveUser(User user) {
        return repository.save(user);
    }

    @Override
    public void deleteUser(User user) {
        repository.delete(user);
    }
}
