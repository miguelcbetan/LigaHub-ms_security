package com.uc.ms_security.entity;

import jakarta.persistence.*;
import lombok.Getter;
import org.hibernate.annotations.ColumnDefault;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "users")
@Getter
@Setter
@NoArgsConstructor
public class User {

    @Id
    @GeneratedValue(
            strategy = GenerationType.IDENTITY
    )
    private Long id;

    @Column(
            nullable = false,
            length = 100
    )
    private String name;

    @Column(
            nullable = false,
            unique = true,
            length = 150
    )
    private String email;

    @Column(
            nullable = false,
            length = 255
    )
    private String password;

    @Column(nullable = false)
    @ColumnDefault("1")
    private boolean active = true;

    /** Segundo factor por correo; solo aplica al acceso con contraseña. */
    @Column(
            name = "two_factor_enabled",
            nullable = false
    )
    @ColumnDefault("0")
    private boolean twoFactorEnabled = false;

    /** Cómo se creó la cuenta: contraseña propia o proveedor externo. */
    @Enumerated(EnumType.STRING)
    @Column(
            name = "auth_method",
            nullable = false,
            length = 20
    )
    @ColumnDefault("'LOCAL'")
    private AuthMethod authMethod = AuthMethod.LOCAL;

    @OneToOne(
            mappedBy = "user",
            cascade = CascadeType.ALL,
            orphanRemoval = true,
            fetch = FetchType.LAZY
    )
    private Profile profile;

    @OneToMany(
            mappedBy = "user",
            cascade = CascadeType.ALL,
            orphanRemoval = true,
            fetch = FetchType.LAZY
    )
    private List<Session> sessions = new ArrayList<>();

    @OneToMany(
            mappedBy = "user",
            cascade = CascadeType.ALL,
            orphanRemoval = true,
            fetch = FetchType.LAZY
    )
    private List<UserRole> userRoles = new ArrayList<>();

    public void addSession(Session session) {
        sessions.add(session);
        session.setUser(this);
    }

    public void removeSession(Session session) {
        sessions.remove(session);
        session.setUser(null);
    }
}