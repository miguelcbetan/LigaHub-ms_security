package com.uc.ms_security;

import com.uc.ms_security.entity.Role;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.CommandLineRunner;

import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

class DatabaseSeederTest extends AbstractAuthTest {

    private static final String[] PERMISOS_TORNEOS = {
            "POST /torneos",
            "GET /torneos",
            "GET /torneos/{id}",
            "PATCH /torneos/{id}",
            "DELETE /torneos/{id}"
    };

    private static final String[] PERMISOS_DEPORTES = {
            "GET /deportes",
            "POST /deportes",
            "GET /deportes/{id}",
            "PATCH /deportes/{id}",
            "DELETE /deportes/{id}"
    };

    private static final String[] PERMISOS_EQUIPOS = {
            "POST /equipos",
            "GET /equipos",
            "GET /equipos/{id}",
            "PATCH /equipos/{id}",
            "DELETE /equipos/{id}",
            "GET /equipos-deportes",
            "POST /equipos-deportes",
            "DELETE /equipos-deportes/{id}"
    };

    @Autowired
    @Qualifier("seedDatabase")
    private CommandLineRunner seedDatabase;

    @Test
    void creaElRolAdministradorDeportivoConSusPermisos() throws Exception {
        seedDatabase.run();
        seedDatabase.run();

        Role role = roleRepository.findByNameIgnoreCase("ADMINISTRADOR DEPORTIVO").orElseThrow();
        Set<String> esperados = Stream.of(PERMISOS_TORNEOS, PERMISOS_DEPORTES, PERMISOS_EQUIPOS)
                .flatMap(Stream::of)
                .collect(Collectors.toSet());

        assertThat(permisosDe("ADMINISTRADOR DEPORTIVO")).isEqualTo(esperados);
        assertThat(rolePermissionRepository.findAllByRoleId(role.getId())).hasSize(18);
    }

    @Test
    void adminYAdministradorDeportivoAdministranDeportes() throws Exception {
        seedDatabase.run();

        assertThat(permisosDe("ADMIN")).contains(PERMISOS_DEPORTES);
        assertThat(permisosDe("ADMINISTRADOR DEPORTIVO")).contains(PERMISOS_DEPORTES);
    }

    @Test
    void soloAdministradorDeportivoGestionaEquipos() throws Exception {
        seedDatabase.run();

        assertThat(permisosDe("ADMINISTRADOR DEPORTIVO")).contains(PERMISOS_EQUIPOS);
        assertThat(permisosDe("ADMIN")).doesNotContain(PERMISOS_EQUIPOS);
    }

    private Set<String> permisosDe(String rol) {
        Role role = roleRepository.findByNameIgnoreCase(rol).orElseThrow();
        return rolePermissionRepository.findAllByRoleId(role.getId()).stream()
                .map(rp -> rp.getPermission().getMethod() + " " + rp.getPermission().getUrl())
                .collect(Collectors.toSet());
    }
}
