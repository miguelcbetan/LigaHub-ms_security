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
            "GET /torneos/{id}/fases",
            "GET /torneos/{id}/desarrollo",
            "GET /torneos/{id}",
            "PATCH /torneos/{id}",
            "DELETE /torneos/{id}"
    };

    private static final String[] PERMISOS_FASES = {
            "POST /fases",
            "GET /fases",
            "GET /fases/{id}",
            "PATCH /fases/{id}",
            "DELETE /fases/{id}"
    };

    private static final String[] PERMISOS_GRUPOS_EQUIPOS = {
            "GET /fases/{id}/equipos",
            "POST /fases/{id}/equipos",
            "DELETE /fases/{id}/equipos/{id}",
            "GET /fases/{id}/partidos"
    };

    private static final String[] PERMISOS_INSCRIPCIONES = {
            "POST /inscripciones",
            "GET /inscripciones/reports/torneo/{torneoId}/count",
            "GET /inscripciones",
            "GET /inscripciones/{id}",
            "PATCH /inscripciones/{id}",
            "DELETE /inscripciones/{id}"
    };

    private static final String[] PERMISOS_ESCENARIOS_TORNEO = {
            "POST /escenarios-torneo",
            "GET /escenarios-torneo/reports/torneo/{torneoId}/count",
            "GET /escenarios-torneo",
            "GET /escenarios-torneo/{id}",
            "PATCH /escenarios-torneo/{id}",
            "DELETE /escenarios-torneo/{id}"
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

    private static final String[] PERMISOS_JUGADORES = {
            "POST /jugadores",
            "GET /jugadores",
            "GET /jugadores/{id}",
            "GET /jugadores/{id}/perfil",
            "PATCH /jugadores/{id}",
            "DELETE /jugadores/{id}",
            "GET /api/users",
            "GET /api/users/{id}"
    };

    private static final String[] PERMISOS_PLANTILLAS = {
            "GET /equipo-jugador",
            "POST /equipo-jugador",
            "PATCH /equipo-jugador/{id}/retiro"
    };

    private static final String[] PERMISOS_HABILIDADES = {
            "POST /habilidades",
            "GET /habilidades",
            "GET /habilidades/{id}",
            "PATCH /habilidades/{id}",
            "DELETE /habilidades/{id}"
    };

    private static final String[] PERMISOS_HABILIDADES_JUGADOR = {
            "POST /habilidad-jugador",
            "GET /habilidad-jugador",
            "DELETE /habilidad-jugador/{id}"
    };

    private static final String[] PERMISOS_AFICIONADOS_DE_EQUIPO = {
            "GET /equipos/{id}/aficionados"
    };

    /** HU-GC-06: gestión de partidos; los escenarios se listan para asociarlos. */
    private static final String[] PERMISOS_PARTIDOS = {
            "POST /partidos",
            "GET /partidos",
            "GET /partidos/{id}",
            "PATCH /partidos/{id}",
            "DELETE /partidos/{id}",
            "GET /escenarios"
    };

    /** HU-GC-07: goles (anotaciones) de los partidos. */
    private static final String[] PERMISOS_ANOTACIONES = {
            "POST /anotaciones",
            "GET /anotaciones",
            "GET /anotaciones/{id}",
            "PATCH /anotaciones/{id}",
            "DELETE /anotaciones/{id}"
    };

    private static final String[] PERMISOS_AFICIONADO = {
            "GET /aficionados/me",
            "POST /aficionados/me",
            "GET /aficionados/me/equipos-disponibles",
            "POST /aficionados/me/equipos",
            "DELETE /aficionados/me/equipos/{id}"
    };

    @Autowired
    @Qualifier("seedDatabase")
    private CommandLineRunner seedDatabase;

    @Test
    void creaElRolAdministradorDeportivoConSusPermisos() throws Exception {
        seedDatabase.run();
        seedDatabase.run();

        Role role = roleRepository.findByNameIgnoreCase("ADMINISTRADOR DEPORTIVO").orElseThrow();
        Set<String> esperados = Stream.of(PERMISOS_TORNEOS, PERMISOS_FASES, PERMISOS_INSCRIPCIONES,
                        PERMISOS_ESCENARIOS_TORNEO, PERMISOS_DEPORTES, PERMISOS_EQUIPOS, PERMISOS_JUGADORES,
                        PERMISOS_PLANTILLAS, PERMISOS_HABILIDADES, PERMISOS_HABILIDADES_JUGADOR,
                        PERMISOS_GRUPOS_EQUIPOS, PERMISOS_AFICIONADOS_DE_EQUIPO, PERMISOS_PARTIDOS,
                        PERMISOS_ANOTACIONES)
                .flatMap(Stream::of)
                .collect(Collectors.toSet());

        assertThat(permisosDe("ADMINISTRADOR DEPORTIVO")).isEqualTo(esperados);
        assertThat(rolePermissionRepository.findAllByRoleId(role.getId())).hasSize(esperados.size());
    }

    @Test
    void soloAdministradorDeportivoGestionaGoles() throws Exception {
        seedDatabase.run();

        assertThat(permisosDe("ADMINISTRADOR DEPORTIVO")).contains(PERMISOS_ANOTACIONES);
        assertThat(permisosDe("ADMIN")).doesNotContain(PERMISOS_ANOTACIONES);
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
        // El ADMIN solo lista equipos (para asignarlos a grupos); no los gestiona.
        assertThat(permisosDe("ADMIN")).contains("GET /equipos");
        assertThat(permisosDe("ADMIN")).doesNotContain(
                "POST /equipos",
                "GET /equipos/{id}",
                "PATCH /equipos/{id}",
                "DELETE /equipos/{id}",
                "GET /equipos-deportes",
                "POST /equipos-deportes",
                "DELETE /equipos-deportes/{id}");
    }

    @Test
    void soloAdministradorDeportivoGestionaJugadores() throws Exception {
        seedDatabase.run();

        assertThat(permisosDe("ADMINISTRADOR DEPORTIVO")).contains(PERMISOS_JUGADORES);
        assertThat(permisosDe("ADMIN")).doesNotContain(
                "POST /jugadores",
                "GET /jugadores",
                "GET /jugadores/{id}",
                "PATCH /jugadores/{id}",
                "DELETE /jugadores/{id}");
    }

    @Test
    void soloAdministradorDeportivoAsignaJugadoresAEquipos() throws Exception {
        seedDatabase.run();

        assertThat(permisosDe("ADMINISTRADOR DEPORTIVO")).contains(PERMISOS_PLANTILLAS);
        assertThat(permisosDe("ADMIN")).doesNotContain(PERMISOS_PLANTILLAS);
    }

    @Test
    void soloAdministradorDeportivoGestionaHabilidades() throws Exception {
        seedDatabase.run();

        assertThat(permisosDe("ADMINISTRADOR DEPORTIVO")).contains(PERMISOS_HABILIDADES);
        assertThat(permisosDe("ADMIN")).doesNotContain(PERMISOS_HABILIDADES);
    }

    @Test
    void soloAdministradorDeportivoAsignaHabilidadesAJugadores() throws Exception {
        seedDatabase.run();

        assertThat(permisosDe("ADMINISTRADOR DEPORTIVO")).contains(PERMISOS_HABILIDADES_JUGADOR);
        assertThat(permisosDe("ADMIN")).doesNotContain(PERMISOS_HABILIDADES_JUGADOR);
    }

    @Test
    void adminYAdministradorDeportivoAsignanEquiposAGrupos() throws Exception {
        seedDatabase.run();

        assertThat(permisosDe("ADMINISTRADOR DEPORTIVO")).contains(PERMISOS_GRUPOS_EQUIPOS);
        assertThat(permisosDe("ADMIN")).contains(PERMISOS_GRUPOS_EQUIPOS);
    }

    @Test
    void cualquierUsuarioRegistradoPuedeVolverseAficionado() throws Exception {
        seedDatabase.run();

        assertThat(permisosDe("USUARIO INICIAL")).contains(PERMISOS_AFICIONADO);
        assertThat(permisosDe("USUARIO INICIAL")).doesNotContain(PERMISOS_AFICIONADOS_DE_EQUIPO);
        assertThat(permisosDe("ADMINISTRADOR DEPORTIVO")).contains(PERMISOS_AFICIONADOS_DE_EQUIPO);
    }

    private Set<String> permisosDe(String rol) {
        Role role = roleRepository.findByNameIgnoreCase(rol).orElseThrow();
        return rolePermissionRepository.findAllByRoleId(role.getId()).stream()
                .map(rp -> rp.getPermission().getMethod() + " " + rp.getPermission().getUrl())
                .collect(Collectors.toSet());
    }
}
