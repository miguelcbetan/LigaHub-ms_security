package com.uc.ms_security.repository;

import com.uc.ms_security.entity.Session;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

public interface SessionRepository
        extends JpaRepository<Session, Long> {

    List<Session> findAllByUserId(Long userId);

    Optional<Session> findByIdAndUserId(
            Long sessionId,
            Long userId
    );

    boolean existsByToken(String token);

    boolean existsByTokenAndIdNot(
            String token,
            Long id
    );

    /** Sesión vigente: existe, no ha expirado y el usuario sigue habilitado. */
    @Query("""
            select count(s) > 0 from Session s
            where s.token = :token
              and s.user.id = :userId
              and s.user.active = true
              and s.expiration > :now
            """)
    boolean existsActive(
            @Param("token") String token,
            @Param("userId") Long userId,
            @Param("now") LocalDateTime now
    );

    @Modifying
    @Query("delete from Session s where s.token = :token and s.user.id = :userId")
    int deleteByTokenAndUserId(
            @Param("token") String token,
            @Param("userId") Long userId
    );

    @Modifying
    @Query("delete from Session s where s.user.id = :userId")
    int deleteAllByUserId(@Param("userId") Long userId);

    @Modifying
    @Query("delete from Session s where s.expiration < :now")
    int deleteExpired(@Param("now") LocalDateTime now);
}
