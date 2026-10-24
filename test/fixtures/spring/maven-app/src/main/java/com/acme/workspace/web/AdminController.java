package com.acme.workspace.web;

import com.acme.workspace.domain.AppUser;
import com.acme.workspace.repo.AppUserRepository;
import com.acme.workspace.service.CurrentUserService;
import com.acme.workspace.web.Dtos.CreateUserRequest;
import com.acme.workspace.web.Dtos.OrganizationResponse;
import com.acme.workspace.web.Dtos.UserResponse;
import jakarta.validation.Valid;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/** Organization administration. Access is restricted to ROLE_ADMIN in SecurityConfig. */
@RestController
@RequestMapping("/api/admin")
public class AdminController {

    private final CurrentUserService currentUser;
    private final AppUserRepository users;

    public AdminController(CurrentUserService currentUser, AppUserRepository users) {
        this.currentUser = currentUser;
        this.users = users;
    }

    @GetMapping("/organization")
    @Transactional(readOnly = true)
    public OrganizationResponse organization() {
        return OrganizationResponse.of(currentUser.require().getOrganization());
    }

    @GetMapping("/users")
    @Transactional(readOnly = true)
    public List<UserResponse> users() {
        return users.findByOrganization_IdOrderByEmail(currentUser.require().getOrgId()).stream()
                .map(UserResponse::of).toList();
    }

    @PostMapping("/users")
    @ResponseStatus(HttpStatus.CREATED)
    @Transactional
    public UserResponse createUser(@Valid @RequestBody CreateUserRequest request) {
        AppUser admin = currentUser.require();
        if (users.existsByEmailIgnoreCase(request.email())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT);
        }
        AppUser created = users.save(new AppUser(UUID.randomUUID(), admin.getOrganization(), request.email(),
                request.displayName(), request.role()));
        return UserResponse.of(created);
    }
}
