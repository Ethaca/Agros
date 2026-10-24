package com.acme.workspace.web;

import com.acme.workspace.service.CurrentUserService;
import com.acme.workspace.service.DocumentService;
import com.acme.workspace.web.Dtos.DocumentRequest;
import com.acme.workspace.web.Dtos.DocumentResponse;
import com.acme.workspace.web.Dtos.PageResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import java.util.List;
import java.util.UUID;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DocumentController {

    private final CurrentUserService currentUser;
    private final DocumentService documents;

    public DocumentController(CurrentUserService currentUser, DocumentService documents) {
        this.currentUser = currentUser;
        this.documents = documents;
    }

    @GetMapping("/api/projects/{projectId}/documents")
    public PageResponse<DocumentResponse> list(@PathVariable Long projectId,
                                               @RequestParam(defaultValue = "0") @Min(0) int page,
                                               @RequestParam(defaultValue = "20") @Min(1) @Max(100) int size) {
        var pageable = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "createdAt"));
        return PageResponse.of(documents.listInProject(currentUser.require(), projectId, pageable),
                DocumentResponse::of);
    }

    @GetMapping("/api/projects/{projectId}/documents/{documentId}")
    public DocumentResponse get(@PathVariable Long projectId, @PathVariable UUID documentId) {
        return DocumentResponse.of(documents.get(currentUser.require(), projectId, documentId));
    }

    @PostMapping("/api/projects/{projectId}/documents")
    @ResponseStatus(HttpStatus.CREATED)
    public DocumentResponse create(@PathVariable Long projectId, @Valid @RequestBody DocumentRequest request) {
        return DocumentResponse.of(documents.create(currentUser.require(), projectId, request.title(),
                request.body()));
    }

    @PutMapping("/api/projects/{projectId}/documents/{documentId}")
    public DocumentResponse update(@PathVariable Long projectId, @PathVariable UUID documentId,
                                   @Valid @RequestBody DocumentRequest request) {
        return DocumentResponse.of(documents.update(currentUser.require(), projectId, documentId,
                request.title(), request.body()));
    }

    @DeleteMapping("/api/projects/{projectId}/documents/{documentId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@PathVariable Long projectId, @PathVariable UUID documentId) {
        documents.delete(currentUser.require(), projectId, documentId);
    }

    @GetMapping("/api/documents/search")
    public PageResponse<DocumentResponse> search(@RequestParam(defaultValue = "") String q,
                                                 @RequestParam(defaultValue = "0") @Min(0) int page,
                                                 @RequestParam(defaultValue = "20") @Min(1) @Max(100) int size) {
        var pageable = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "createdAt"));
        return PageResponse.of(documents.search(currentUser.require(), q, pageable), DocumentResponse::of);
    }

    @GetMapping("/api/documents/export")
    public List<DocumentResponse> export() {
        return documents.export(currentUser.require()).stream().map(DocumentResponse::of).toList();
    }
}
