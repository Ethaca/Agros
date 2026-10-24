package com.acme.workspace.repo;

import com.acme.workspace.domain.Document;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface DocumentRepository extends JpaRepository<Document, UUID> {

    Optional<Document> findByIdAndProjectIdAndOrgId(UUID id, Long projectId, UUID orgId);

    Optional<Document> findByIdAndProjectIdAndOrgIdAndOwnerId(UUID id, Long projectId, UUID orgId, UUID ownerId);

    Page<Document> findByProjectIdAndOrgIdAndOwnerId(Long projectId, UUID orgId, UUID ownerId, Pageable pageable);

    @Query("""
            select d from Document d
            where d.orgId = :orgId and d.ownerId = :ownerId
              and (lower(d.title) like lower(concat('%', :q, '%'))
                   or lower(d.body) like lower(concat('%', :q, '%')))
            """)
    Page<Document> search(@Param("orgId") UUID orgId, @Param("ownerId") UUID ownerId,
                          @Param("q") String q, Pageable pageable);

    List<Document> findByOrgIdAndOwnerIdOrderByCreatedAtDesc(UUID orgId, UUID ownerId);
}
