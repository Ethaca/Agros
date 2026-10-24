package com.acme.workspace.service;

import com.acme.workspace.domain.AppUser;
import com.acme.workspace.domain.Project;
import com.acme.workspace.domain.ProjectStatus;
import com.acme.workspace.repo.ProjectRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
@Transactional(readOnly = true)
public class ProjectService {

    private final ProjectRepository projects;

    public ProjectService(ProjectRepository projects) {
        this.projects = projects;
    }

    public Page<Project> list(AppUser caller, String q, Pageable pageable) {
        return projects.findByOrgIdAndNameContainingIgnoreCase(caller.getOrgId(), q == null ? "" : q, pageable);
    }

    /** Loads a project by id, or 404. */
    public Project get(AppUser caller, Long projectId) {
        return projects.findById(projectId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
    }

    @Transactional
    public Project create(AppUser caller, String name, String description) {
        return projects.save(new Project(caller.getOrgId(), name, description));
    }

    @Transactional
    public Project update(AppUser caller, Long projectId, String name, String description, ProjectStatus status) {
        Project project = get(caller, projectId);
        project.setName(name);
        project.setDescription(description);
        if (status != null) {
            project.setStatus(status);
        }
        return project;
    }
}
