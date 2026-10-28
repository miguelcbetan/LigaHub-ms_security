package com.uc.ms_security.repository;

import com.uc.ms_security.entity.TwoFactorChallenge;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.Optional;

public interface TwoFactorChallengeRepository
        extends JpaRepository<TwoFactorChallenge, String> {

    /** Bloqueo de escritura: evita que intentos simultáneos burlen el límite. */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @EntityGraph(attributePaths = {"user"})
    @Query("select c from TwoFactorChallenge c where c.id = :id")
    Optional<TwoFactorChallenge> findForVerification(@Param("id") String id);

    @Modifying
    @Query("update TwoFactorChallenge c set c.consumed = true "
            + "where c.user.id = :userId and c.consumed = false")
    int invalidatePendingByUserId(@Param("userId") Long userId);

    @Modifying
    @Query("delete from TwoFactorChallenge c where c.expiresAt < :limit")
    int deleteOlderThan(@Param("limit") LocalDateTime limit);
}
