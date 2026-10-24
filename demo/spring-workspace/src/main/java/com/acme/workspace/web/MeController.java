package com.acme.workspace.web;

import com.acme.workspace.service.CurrentUserService;
import com.acme.workspace.web.Dtos.MeResponse;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MeController {

    private final CurrentUserService currentUser;

    public MeController(CurrentUserService currentUser) {
        this.currentUser = currentUser;
    }

    @GetMapping("/api/me")
    @Transactional(readOnly = true)
    public MeResponse me() {
        return MeResponse.of(currentUser.require());
    }
}
