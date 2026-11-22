package com.uc.ms_security.config;

import com.uc.ms_security.entity.Permission;
import com.uc.ms_security.entity.Role;
import com.uc.ms_security.entity.RolePermission;
import com.uc.ms_security.entity.User;
import com.uc.ms_security.entity.UserRole;
import com.uc.ms_security.repository.PermissionRepository;
import com.uc.ms_security.repository.RolePermissionRepository;
import com.uc.ms_security.repository.RoleRepository;
import com.uc.ms_security.repository.UserRepository;
import com.uc.ms_security.repository.UserRoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@RequiredArgsConstructor
public class DatabaseSeeder {

    private static final PermissionSeed[] ADMIN_PERMISSIONS = {
            new PermissionSeed("GET", "/api/users", "User"),
            new PermissionSeed("POST", "/api/users", "User"),
            new PermissionSeed("GET", "/api/users/{id}", "User"),
            new PermissionSeed("PUT", "/api/users/{id}", "User"),
            new PermissionSeed("DELETE", "/api/users/{id}", "User"),
            new PermissionSeed("PUT", "/api/users/{id}/status", "User"),
            new PermissionSeed("GET", "/api/users/{id}/profile", "Profile"),
            new PermissionSeed("GET", "/api/users/{id}/detail-with-sessions", "User"),
            new PermissionSeed("GET", "/api/users/{id}/detail-with-roles", "User"),
            new PermissionSeed("POST", "/api/users/{id}/profile", "Profile"),
            new PermissionSeed("PUT", "/api/users/{id}/profile", "Profile"),
            new PermissionSeed("DELETE", "/api/users/{id}/profile", "Profile"),
            new PermissionSeed("GET", "/api/profile/me", "Profile"),
            new PermissionSeed("PUT", "/api/profile/me", "Profile"),
            new PermissionSeed("GET", "/api/roles", "Role"),
            new PermissionSeed("POST", "/api/roles", "Role"),
            new PermissionSeed("GET", "/api/roles/{id}", "Role"),
            new PermissionSeed("PUT", "/api/roles/{id}", "Role"),
            new PermissionSeed("DELETE", "/api/roles/{id}", "Role"),
            new PermissionSeed("GET", "/api/permissions", "Permission"),
            new PermissionSeed("POST", "/api/permissions", "Permission"),
            new PermissionSeed("GET", "/api/permissions/{id}", "Permission"),
            new PermissionSeed("PUT", "/api/permissions/{id}", "Permission"),
            new PermissionSeed("DELETE", "/api/permissions/{id}", "Permission"),
            new PermissionSeed("GET", "/api/roles/{id}/detail-with-permissions", "Role"),
            new PermissionSeed("GET", "/api/user-roles", "UserRole"),
            new PermissionSeed("POST", "/api/user-roles", "UserRole"),
            new PermissionSeed("GET", "/api/user-roles/users/{id}", "UserRole"),
            new PermissionSeed("GET", "/api/user-roles/roles/{id}", "UserRole"),
            new PermissionSeed("DELETE", "/api/user-roles/{id}/{id}", "UserRole"),
            new PermissionSeed("GET", "/api/role-permissions", "RolePermission"),
            new PermissionSeed("POST", "/api/role-permissions", "RolePermission"),
            new PermissionSeed("GET", "/api/role-permissions/roles/{id}", "RolePermission"),
            new PermissionSeed("GET", "/api/role-permissions/permissions/{id}", "RolePermission"),
            new PermissionSeed("DELETE", "/api/role-permissions/{id}/{id}", "RolePermission"),
            new PermissionSeed("GET", "/api/users/{id}/sessions", "Session"),
            new PermissionSeed("DELETE", "/api/users/{id}/sessions/{id}", "Session"),
            new PermissionSeed("POST", "/torneos", "Torneo"),
            new PermissionSeed("GET", "/torneos", "Torneo"),
            new PermissionSeed("GET", "/torneos/{id}/fases", "Torneo"),
            new PermissionSeed("GET", "/torneos/{id}", "Torneo"),
            new PermissionSeed("PATCH", "/torneos/{id}", "Torneo"),
            new PermissionSeed("DELETE", "/torneos/{id}", "Torneo"),
            new PermissionSeed("POST", "/fases", "Fase"),
            new PermissionSeed("GET", "/fases", "Fase"),
            new PermissionSeed("GET", "/fases/{id}", "Fase"),
            new PermissionSeed("PATCH", "/fases/{id}", "Fase"),
            new PermissionSeed("DELETE", "/fases/{id}", "Fase"),
            new PermissionSeed("POST", "/inscripciones", "Inscripcion"),
            new PermissionSeed("GET", "/inscripciones/reports/torneo/{torneoId}/count", "Inscripcion"),
            new PermissionSeed("GET", "/inscripciones", "Inscripcion"),
            new PermissionSeed("GET", "/inscripciones/{id}", "Inscripcion"),
            new PermissionSeed("PATCH", "/inscripciones/{id}", "Inscripcion"),
            new PermissionSeed("DELETE", "/inscripciones/{id}", "Inscripcion"),
            new PermissionSeed("POST", "/escenarios-torneo", "EscenarioTorneo"),
            new PermissionSeed("GET", "/escenarios-torneo/reports/torneo/{torneoId}/count", "EscenarioTorneo"),
            new PermissionSeed("GET", "/escenarios-torneo", "EscenarioTorneo"),
            new PermissionSeed("GET", "/escenarios-torneo/{id}", "EscenarioTorneo"),
            new PermissionSeed("PATCH", "/escenarios-torneo/{id}", "EscenarioTorneo"),
            new PermissionSeed("DELETE", "/escenarios-torneo/{id}", "EscenarioTorneo"),
            new PermissionSeed("GET", "/deportes", "Deporte"),
            new PermissionSeed("POST", "/deportes", "Deporte"),
            new PermissionSeed("GET", "/deportes/{id}", "Deporte"),
            new PermissionSeed("PATCH", "/deportes/{id}", "Deporte"),
            new PermissionSeed("DELETE", "/deportes/{id}", "Deporte"),
            new PermissionSeed("GET", "/equipos", "Equipo"),
            new PermissionSeed("GET", "/fases/{id}/equipos", "Fase"),
            new PermissionSeed("POST", "/fases/{id}/equipos", "Fase"),
            new PermissionSeed("DELETE", "/fases/{id}/equipos/{id}", "Fase"),
            new PermissionSeed("GET", "/fases/{id}/partidos", "Fase")
    };

    private static final PermissionSeed[] SPORTS_ADMIN_PERMISSIONS = {
            new PermissionSeed("POST", "/torneos", "Torneo"),
            new PermissionSeed("GET", "/torneos", "Torneo"),
            new PermissionSeed("GET", "/torneos/{id}/fases", "Torneo"),
            new PermissionSeed("GET", "/torneos/{id}", "Torneo"),
            new PermissionSeed("PATCH", "/torneos/{id}", "Torneo"),
            new PermissionSeed("DELETE", "/torneos/{id}", "Torneo"),
            new PermissionSeed("POST", "/fases", "Fase"),
            new PermissionSeed("GET", "/fases", "Fase"),
            new PermissionSeed("GET", "/fases/{id}", "Fase"),
            new PermissionSeed("PATCH", "/fases/{id}", "Fase"),
            new PermissionSeed("DELETE", "/fases/{id}", "Fase"),
            new PermissionSeed("POST", "/inscripciones", "Inscripcion"),
            new PermissionSeed("GET", "/inscripciones/reports/torneo/{torneoId}/count", "Inscripcion"),
            new PermissionSeed("GET", "/inscripciones", "Inscripcion"),
            new PermissionSeed("GET", "/inscripciones/{id}", "Inscripcion"),
            new PermissionSeed("PATCH", "/inscripciones/{id}", "Inscripcion"),
            new PermissionSeed("DELETE", "/inscripciones/{id}", "Inscripcion"),
            new PermissionSeed("POST", "/escenarios-torneo", "EscenarioTorneo"),
            new PermissionSeed("GET", "/escenarios-torneo/reports/torneo/{torneoId}/count", "EscenarioTorneo"),
            new PermissionSeed("GET", "/escenarios-torneo", "EscenarioTorneo"),
            new PermissionSeed("GET", "/escenarios-torneo/{id}", "EscenarioTorneo"),
            new PermissionSeed("PATCH", "/escenarios-torneo/{id}", "EscenarioTorneo"),
            new PermissionSeed("DELETE", "/escenarios-torneo/{id}", "EscenarioTorneo"),
            new PermissionSeed("GET", "/deportes", "Deporte"),
            new PermissionSeed("POST", "/deportes", "Deporte"),
            new PermissionSeed("GET", "/deportes/{id}", "Deporte"),
            new PermissionSeed("PATCH", "/deportes/{id}", "Deporte"),
            new PermissionSeed("DELETE", "/deportes/{id}", "Deporte"),
            new PermissionSeed("POST", "/equipos", "Equipo"),
            new PermissionSeed("GET", "/equipos", "Equipo"),
            new PermissionSeed("GET", "/equipos/{id}", "Equipo"),
            new PermissionSeed("PATCH", "/equipos/{id}", "Equipo"),
            new PermissionSeed("DELETE", "/equipos/{id}", "Equipo"),
            new PermissionSeed("GET", "/equipos-deportes", "EquipoDeporte"),
            new PermissionSeed("POST", "/equipos-deportes", "EquipoDeporte"),
            new PermissionSeed("DELETE", "/equipos-deportes/{id}", "EquipoDeporte"),
            new PermissionSeed("GET", "/fases/{id}/equipos", "Fase"),
            new PermissionSeed("POST", "/fases/{id}/equipos", "Fase"),
            new PermissionSeed("DELETE", "/fases/{id}/equipos/{id}", "Fase"),
            new PermissionSeed("GET", "/fases/{id}/partidos", "Fase"),
            new PermissionSeed("POST", "/jugadores", "Jugador"),
            new PermissionSeed("GET", "/jugadores", "Jugador"),
            new PermissionSeed("GET", "/jugadores/{id}", "Jugador"),
            new PermissionSeed("GET", "/jugadores/{id}/perfil", "Jugador"),
            new PermissionSeed("PATCH", "/jugadores/{id}", "Jugador"),
            new PermissionSeed("DELETE", "/jugadores/{id}", "Jugador"),
            new PermissionSeed("GET", "/equipo-jugador", "EquipoJugador"),
            new PermissionSeed("POST", "/equipo-jugador", "EquipoJugador"),
            new PermissionSeed("PATCH", "/equipo-jugador/{id}/retiro", "EquipoJugador"),
            new PermissionSeed("POST", "/habilidades", "Habilidad"),
            new PermissionSeed("GET", "/habilidades", "Habilidad"),
            new PermissionSeed("GET", "/habilidades/{id}", "Habilidad"),
            new PermissionSeed("PATCH", "/habilidades/{id}", "Habilidad"),
            new PermissionSeed("DELETE", "/habilidades/{id}", "Habilidad"),
            new PermissionSeed("POST", "/habilidad-jugador", "HabilidadJugador"),
            new PermissionSeed("GET", "/habilidad-jugador", "HabilidadJugador"),
            new PermissionSeed("DELETE", "/habilidad-jugador/{id}", "HabilidadJugador"),
            new PermissionSeed("GET", "/equipos/{id}/aficionados", "AficionadoEquipo"),
            new PermissionSeed("GET", "/api/users", "User"),
            new PermissionSeed("GET", "/api/users/{id}", "User")
    };

    /** HU-GE-05: cualquier usuario registrado puede volverse aficionado y elegir sus equipos. */
    private static final PermissionSeed[] AFICIONADO_PERMISSIONS = {
            new PermissionSeed("GET", "/aficionados/me", "Aficionado"),
            new PermissionSeed("POST", "/aficionados/me", "Aficionado"),
            new PermissionSeed("GET", "/aficionados/me/equipos-disponibles", "Aficionado"),
            new PermissionSeed("POST", "/aficionados/me/equipos", "Aficionado"),
            new PermissionSeed("DELETE", "/aficionados/me/equipos/{id}", "Aficionado")
    };

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final UserRoleRepository userRoleRepository;
    private final RolePermissionRepository rolePermissionRepository;
    private final PasswordEncoder passwordEncoder;

    @Bean
    CommandLineRunner seedDatabase() {
        return arguments -> {
            Role adminRole = findOrCreateRole("ADMIN", "Administrador");
            Role consultantRole = findOrCreateRole(
                    "CONSULTOR",
                    "Consulta de usuarios");

            Role initialRole = findOrCreateRole(
                    "USUARIO INICIAL",
                    "Rol inicial para usuarios registrados");
            Role sportsAdminRole = findOrCreateRole(
                    "ADMINISTRADOR DEPORTIVO",
                    "Gestión de torneos y competencias deportivas");

            User adminUser = findOrCreateUser();
            assignRole(adminUser, adminRole);

            for (PermissionSeed seed : ADMIN_PERMISSIONS) {
                Permission permission = findOrCreatePermission(seed);
                assignPermission(adminRole, permission);
            }

            for (PermissionSeed seed : SPORTS_ADMIN_PERMISSIONS) {
                assignPermission(sportsAdminRole, findOrCreatePermission(seed));
            }

            Permission listUsers = findOrCreatePermission(
                    new PermissionSeed("GET", "/api/users", "User"));
            Permission getUser = findOrCreatePermission(
                    new PermissionSeed("GET", "/api/users/{id}", "User"));
            assignPermission(consultantRole, listUsers);
            assignPermission(consultantRole, getUser);

            assignPermission(initialRole, findOrCreatePermission(
                    new PermissionSeed("GET", "/api/profile/me", "Profile")));
            assignPermission(initialRole, findOrCreatePermission(
                    new PermissionSeed("PUT", "/api/profile/me", "Profile")));

            for (PermissionSeed seed : AFICIONADO_PERMISSIONS) {
                assignPermission(initialRole, findOrCreatePermission(seed));
            }
        };
    }

    private Role findOrCreateRole(String name, String description) {
        return roleRepository.findByNameIgnoreCase(name)
                .orElseGet(() -> {
                    Role role = new Role();
                    role.setName(name);
                    role.setDescription(description);
                    return roleRepository.save(role);
                });
    }

    private User findOrCreateUser() {
        return userRepository.findByEmail("admin@uc.edu.co")
                .orElseGet(() -> {
                    User user = new User();
                    user.setName("Administrador");
                    user.setEmail("admin@uc.edu.co");
                    user.setPassword(passwordEncoder.encode("Admin123!"));
                    return userRepository.save(user);
                });
    }

    private Permission findOrCreatePermission(PermissionSeed seed) {
        Permission permission = permissionRepository.findByUrlAndMethod(seed.url(), seed.method())
                .orElseGet(() -> {
                    Permission created = new Permission();
                    created.setUrl(seed.url());
                    created.setMethod(seed.method());
                    created.setModel(seed.model());
                    return permissionRepository.save(created);
                });
        if (permission.getModel() == null || permission.getModel().isBlank()) {
            permission.setModel(seed.model());
            permission = permissionRepository.save(permission);
        }
        return permission;
    }

    private void assignRole(User user, Role role) {
        if (!userRoleRepository.existsByUserIdAndRoleId(
                user.getId(),
                role.getId())) {
            UserRole userRole = new UserRole();
            userRole.setUser(user);
            userRole.setRole(role);
            userRoleRepository.save(userRole);
        }
    }

    private void assignPermission(Role role, Permission permission) {
        if (!rolePermissionRepository.existsByRoleIdAndPermissionId(
                role.getId(),
                permission.getId())) {
            RolePermission rolePermission = new RolePermission();
            rolePermission.setRole(role);
            rolePermission.setPermission(permission);
            rolePermissionRepository.save(rolePermission);
        }
    }

    private record PermissionSeed(String method, String url, String model) {
    }
}
