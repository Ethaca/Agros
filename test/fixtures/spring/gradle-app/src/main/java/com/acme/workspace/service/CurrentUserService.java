package com.acme.workspace.service;

import com.acme.workspace.domain.AppUser;
import com.acme.workspace.repo.AppUserRepository;
import java.util.Optional;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

/**
 * Resolves the authenticated caller to an app_users row. The JWT {@code sub} is the user id (UUID);
 * tokens whose {@code sub} is not a UUID are matched by email instead.
 */
@Service
public class CurrentUserService {

    private final AppUserRepository users;

    public CurrentUserService(AppUserRepository users) {
        this.users = users;
    }

    public AppUser require() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !(auth.getPrincipal() instanceof Jwt jwt)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        }
        return lookup(jwt.getSubject())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.FORBIDDEN));
    }

    private Optional<AppUser> lookup(String subject) {
        if (subject == null || subject.isBlank()) {
            return Optional.empty();
        }
        try {
            return users.findById(UUID.fromString(subject));
        } catch (IllegalArgumentException notUuid) {
            return users.findByEmailIgnoreCase(subject);
        }
    }
}
