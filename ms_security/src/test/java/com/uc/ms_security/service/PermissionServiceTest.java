package com.uc.ms_security.service;

import com.uc.ms_security.mapper.PermissionMapper;
import com.uc.ms_security.repository.PermissionRepository;
import com.uc.ms_security.repository.RolePermissionRepository;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class PermissionServiceTest {

    private final PermissionRepository permissionRepository = mock(PermissionRepository.class);
    private final PermissionService permissionService = new PermissionService(
            permissionRepository,
            mock(RolePermissionRepository.class),
            mock(PermissionMapper.class)
    );

    @Test
    void normalizesUuidPathSegmentsBeforeCheckingThePermission() {
        when(permissionRepository.findByUserIdAndMethodAndUrl(
                7L,
                "GET",
                "/torneos/{id}/fases"
        )).thenReturn(List.of());

        permissionService.hasPermission(
                7L,
                "GET",
                "/torneos/550e8400-e29b-41d4-a716-446655440000/fases"
        );

        verify(permissionRepository).findByUserIdAndMethodAndUrl(
                7L,
                "GET",
                "/torneos/{id}/fases"
        );
    }
}
