package com.acme.workspace.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "documents")
public class Document {

    @Id
    private UUID id;

    @Column(name = "org_id", nullable = false)
    private UUID orgId;

    @Column(name = "project_id", nullable = false)
    private Long projectId;

    @Column(name = "owner_id", nullable = false)
    private UUID ownerId;

    @Column(nullable = false, length = 200)
    private String title;

    @Column(nullable = false, columnDefinition = "text")
    private String body;

    /** Secret link token for external sharing. Never returned by the API. */
    @Column(name = "share_token", nullable = false, length = 64)
    private String shareToken;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt = Instant.now();

    protected Document() {
    }

    public Document(UUID orgId, Long projectId, UUID ownerId, String title, String body, String shareToken) {
        this.id = UUID.randomUUID();
        this.orgId = orgId;
        this.projectId = projectId;
        this.ownerId = ownerId;
        this.title = title;
        this.body = body;
        this.shareToken = shareToken;
    }

    public void update(String title, String body) {
        this.title = title;
        this.body = body;
        this.updatedAt = Instant.now();
    }

    public UUID getId() {
        return id;
    }

    public UUID getOrgId() {
        return orgId;
    }

    public Long getProjectId() {
        return projectId;
    }

    public UUID getOwnerId() {
        return ownerId;
    }

    public String getTitle() {
        return title;
    }

    public String getBody() {
        return body;
    }

    public String getShareToken() {
        return shareToken;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }
}
