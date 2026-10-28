package com.uc.ms_security.repository;

import com.uc.ms_security.entity.ExternalIdentity;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface ExternalIdentityRepository
        extends JpaRepository<ExternalIdentity, Long> {

    @EntityGraph(attributePaths = {"user"})
    Optional<ExternalIdentity> findByProviderAndProviderUid(
            String provider,
            String providerUid
    );

    long countByProviderAndProviderUid(
            String provider,
            String providerUid
    );
}
