package com.acme.workspace.service;

import com.acme.workspace.domain.AppUser;
import com.acme.workspace.domain.Document;
import com.acme.workspace.repo.DocumentRepository;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

/** Documents are private to their owner within the owner's organization. */
@Service
@Transactional(readOnly = true)
public class DocumentService {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final DocumentRepository documents;
    private final ProjectService projects;

    public DocumentService(DocumentRepository documents, ProjectService projects) {
        this.documents = documents;
        this.projects = projects;
    }

    public Page<Document> listInProject(AppUser caller, Long projectId, Pageable pageable) {
        projects.get(caller, projectId);
        return documents.findByProjectIdAndOrgIdAndOwnerId(projectId, caller.getOrgId(), caller.getId(), pageable);
    }

    public Page<Document> search(AppUser caller, String q, Pageable pageable) {
        return documents.search(caller.getOrgId(), caller.getId(), q == null ? "" : q, pageable);
    }

    public List<Document> export(AppUser caller) {
        return documents.findByOrgIdAndOwnerIdOrderByCreatedAtDesc(caller.getOrgId(), caller.getId());
    }

    public Document get(AppUser caller, Long projectId, UUID documentId) {
        return documents.findByIdAndProjectIdAndOrgIdAndOwnerId(documentId, projectId, caller.getOrgId(), caller.getId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
    }

    @Transactional
    public Document create(AppUser caller, Long projectId, String title, String body) {
        projects.get(caller, projectId);
        byte[] token = new byte[24];
        RANDOM.nextBytes(token);
        return documents.save(new Document(caller.getOrgId(), projectId, caller.getId(), title, body,
                "shr_" + HexFormat.of().formatHex(token)));
    }

    @Transactional
    public Document update(AppUser caller, Long projectId, UUID documentId, String title, String body) {
        Document doc = get(caller, projectId, documentId);
        doc.update(title, body);
        return doc;
    }

    @Transactional
    public void delete(AppUser caller, Long projectId, UUID documentId) {
        documents.delete(get(caller, projectId, documentId));
    }
}
