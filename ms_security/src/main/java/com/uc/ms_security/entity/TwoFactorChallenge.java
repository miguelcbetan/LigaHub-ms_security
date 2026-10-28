package com.uc.ms_security.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

/**
 * Estado "credenciales verificadas, segundo factor pendiente". No es una
 * sesión: no autoriza ninguna ruta protegida. Solo guarda el hash del código.
 */
@Entity
@Table(name = "two_factor_challenges")
@Getter
@Setter
@NoArgsConstructor
public class TwoFactorChallenge {

    @Id
    @Column(length = 36)
    private String id;

    @Column(
            name = "code_hash",
            nullable = false,
            length = 64
    )
    private String codeHash;

    @Column(
            name = "expires_at",
            nullable = false
    )
    private LocalDateTime expiresAt;

    @Column(nullable = false)
    private int attempts = 0;

    @Column(nullable = false)
    private boolean consumed = false;

    @Column(
            name = "created_at",
            nullable = false
    )
    private LocalDateTime createdAt = LocalDateTime.now();

    @ManyToOne(
            fetch = FetchType.LAZY,
            optional = false
    )
    @JoinColumn(
            name = "user_id",
            nullable = false
    )
    private User user;
}
