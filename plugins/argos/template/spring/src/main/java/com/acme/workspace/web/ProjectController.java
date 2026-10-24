package com.acme.workspace.web;

import com.acme.workspace.service.CurrentUserService;
import com.acme.workspace.service.ProjectService;
import com.acme.workspace.web.Dtos.PageResponse;
import com.acme.workspace.web.Dtos.ProjectRequest;
import com.acme.workspace.web.Dtos.ProjectResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/projects")
public class ProjectController {

    private final CurrentUserService currentUser;
    private final ProjectService projects;

    public ProjectController(CurrentUserService currentUser, ProjectService projects) {
        this.currentUser = currentUser;
        this.projects = projects;
    }

    @GetMapping
    public PageResponse<ProjectResponse> list(@RequestParam(required = false) String q,
                                              @RequestParam(defaultValue = "0") @Min(0) int page,
                                              @RequestParam(defaultValue = "20") @Min(1) @Max(100) int size) {
        var pageable = PageRequest.of(page, size, Sort.by("id"));
        return PageResponse.of(projects.list(currentUser.require(), q, pageable), ProjectResponse::of);
    }

    @GetMapping("/{projectId}")
    public ProjectResponse get(@PathVariable Long projectId) {
        return ProjectResponse.of(projects.get(currentUser.require(), projectId));
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasRole('ADMIN')")
    public ProjectResponse create(@Valid @RequestBody ProjectRequest request) {
        return ProjectResponse.of(projects.create(currentUser.require(), request.name(), request.description()));
    }

    @PutMapping("/{projectId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ProjectResponse update(@PathVariable Long projectId, @Valid @RequestBody ProjectRequest request) {
        return ProjectResponse.of(projects.update(currentUser.require(), projectId, request.name(),
                request.description(), request.status()));
    }
}
