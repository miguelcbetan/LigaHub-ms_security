package com.uc.ms_security.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

/**
 * Identidad de un proveedor externo (Google, GitHub, Microsoft vía Firebase)
 * vinculada a un usuario interno. La unicidad (proveedor, uid) impide
 * duplicados incluso con solicitudes simultáneas.
 */
@Entity
@Table(
        name = "external_identities",
        uniqueConstraints = {
                @UniqueConstraint(
                        name = "uk_external_identity_provider_uid",
                        columnNames = {"provider", "provider_uid"}
                )
        }
)
@Getter
@Setter
@NoArgsConstructor
public class ExternalIdentity {

    @Id
    @GeneratedValue(
            strategy = GenerationType.IDENTITY
    )
    private Long id;

    @Column(
            nullable = false,
            length = 50
    )
    private String provider;

    @Column(
            name = "provider_uid",
            nullable = false,
            length = 128
    )
    private String providerUid;

    @Column(
            nullable = false,
            length = 150
    )
    private String email;

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
