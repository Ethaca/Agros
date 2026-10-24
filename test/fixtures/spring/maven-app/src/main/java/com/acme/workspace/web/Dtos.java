package com.acme.workspace.web;

import com.acme.workspace.domain.AppUser;
import com.acme.workspace.domain.Document;
import com.acme.workspace.domain.Organization;
import com.acme.workspace.domain.Project;
import com.acme.workspace.domain.ProjectStatus;
import com.acme.workspace.domain.Role;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.function.Function;
import org.springframework.data.domain.Page;

/** Request/response DTOs. Entities are never serialized directly. */
public final class Dtos {

    private Dtos() {
    }

    public record MeResponse(UUID id, String email, String displayName, Role role, UUID orgId, String orgName) {
        static MeResponse of(AppUser u) {
            return new MeResponse(u.getId(), u.getEmail(), u.getDisplayName(), u.getRole(),
                    u.getOrgId(), u.getOrganization().getName());
        }
    }

    public record OrganizationResponse(UUID id, String name, String slug) {
        static OrganizationResponse of(Organization o) {
            return new OrganizationResponse(o.getId(), o.getName(), o.getSlug());
        }
    }

    public record UserResponse(UUID id, String email, String displayName, Role role) {
        static UserResponse of(AppUser u) {
            return new UserResponse(u.getId(), u.getEmail(), u.getDisplayName(), u.getRole());
        }
    }

    public record CreateUserRequest(
            @NotBlank @Email @Size(max = 254) String email,
            @NotBlank @Size(max = 100) String displayName,
            @NotNull Role role) {
    }

    public record ProjectResponse(Long id, UUID orgId, String name, String description, ProjectStatus status,
                                  Instant createdAt) {
        static ProjectResponse of(Project p) {
            return new ProjectResponse(p.getId(), p.getOrgId(), p.getName(), p.getDescription(), p.getStatus(),
                    p.getCreatedAt());
        }
    }

    public record ProjectRequest(
            @NotBlank @Size(max = 120) String name,
            @Size(max = 2000) String description,
            ProjectStatus status) {
    }

    public record DocumentResponse(UUID id, Long projectId, UUID ownerId, String title, String body,
                                   Instant createdAt, Instant updatedAt) {
        static DocumentResponse of(Document d) {
            return new DocumentResponse(d.getId(), d.getProjectId(), d.getOwnerId(), d.getTitle(), d.getBody(),
                    d.getCreatedAt(), d.getUpdatedAt());
        }
    }

    public record DocumentRequest(
            @NotBlank @Size(max = 200) String title,
            @NotBlank @Size(max = 20000) String body) {
    }

    public record PageResponse<T>(List<T> content, int page, int size, long totalElements, int totalPages) {
        static <E, T> PageResponse<T> of(Page<E> page, Function<E, T> mapper) {
            return new PageResponse<>(page.getContent().stream().map(mapper).toList(), page.getNumber(),
                    page.getSize(), page.getTotalElements(), page.getTotalPages());
        }
    }
}
