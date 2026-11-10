package com.uc.ms_security.service;

import com.uc.ms_security.dto.permissions.PermissionRequestDTO;
import com.uc.ms_security.dto.permissions.PermissionResponseDTO;
import com.uc.ms_security.entity.Permission;
import com.uc.ms_security.exception.ApplicationException;
import com.uc.ms_security.exception.ErrorCase;
import com.uc.ms_security.mapper.PermissionMapper;
import com.uc.ms_security.repository.PermissionRepository;
import com.uc.ms_security.repository.RolePermissionRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Locale;

@Service
@RequiredArgsConstructor
public class PermissionService {

    private final PermissionRepository permissionRepository;
    private final RolePermissionRepository rolePermissionRepository;
    private final PermissionMapper permissionMapper;

    public boolean hasPermission(
            Long userId,
            String httpMethod,
            String requestUrl) {

        String normalizedUrl = normalizeUrl(requestUrl);

        return permissionRepository
                .findByUserIdAndMethodAndUrl(
                        userId,
                        httpMethod.toUpperCase(Locale.ROOT),
                        normalizedUrl
                )
                .stream()
                .findAny()
                .isPresent();
    }

    public PermissionResponseDTO create(PermissionRequestDTO dto) {
        normalize(dto);

        if (permissionRepository.existsByUrlAndMethod(
                dto.getUrl(), dto.getMethod())) {
            throw new ApplicationException(
                    ErrorCase.ALREADY_EXISTS,
                    "Ya existe un permiso con esa url y método"
            );
        }

        Permission permission = permissionMapper.toEntity(dto);

        return permissionMapper.toResponseDTO(
                permissionRepository.save(permission)
        );
    }

    public List<PermissionResponseDTO> findAll() {
        return permissionMapper.toResponseDTOList(
                permissionRepository.findAll()
        );
    }

    public PermissionResponseDTO findById(Long id) {
        return permissionMapper.toResponseDTO(
                findEntityById(id)
        );
    }

    public PermissionResponseDTO update(
            Long id,
            PermissionRequestDTO dto) {

        Permission permission = findEntityById(id);

        normalize(dto);

        if (permissionRepository.existsByUrlAndMethodAndIdNot(
                dto.getUrl(), dto.getMethod(), id)) {
            throw new ApplicationException(
                    ErrorCase.ALREADY_EXISTS,
                    "Ya existe un permiso con esa url y método"
            );
        }

        permissionMapper.updateEntity(dto, permission);

        return permissionMapper.toResponseDTO(
                permissionRepository.save(permission)
        );
    }

    public void delete(Long id) {
        Permission permission = findEntityById(id);

        if (rolePermissionRepository.existsByPermissionId(id)) {
            throw new ApplicationException(
                    ErrorCase.INVALID_OPERATION,
                    "No se puede eliminar un permiso que está asignado"
            );
        }

        permissionRepository.delete(permission);
    }

    /**
     * Deja el método y la URL en la forma que usa el autorizador (método en
     * mayúsculas y parámetros de ruta como {id}), de modo que dos permisos
     * equivalentes sean el mismo y todo permiso guardado pueda coincidir con
     * una petición real.
     */
    private void normalize(PermissionRequestDTO dto) {
        dto.setMethod(dto.getMethod().trim().toUpperCase(Locale.ROOT));

        String url = dto.getUrl().trim();
        if (url.length() > 1 && url.endsWith("/")) {
            url = url.substring(0, url.length() - 1);
        }

        String[] segments = url.split("/", -1);
        for (int index = 0; index < segments.length; index++) {
            String segment = segments[index];
            boolean isPathParameter = segment.matches("\\{[^}]*}")
                    || segment.matches(":[A-Za-z_]\\w*");
            if (isPathParameter) {
                segments[index] = "{id}";
            }
        }
        dto.setUrl(String.join("/", segments));
    }

    private Permission findEntityById(Long id) {
        return permissionRepository.findById(id)
                .orElseThrow(
                        () -> new ApplicationException(
                                ErrorCase.NOT_FOUND,
                                "Permiso no encontrado"
                        )
                );
    }

        private String normalizeUrl(String requestUrl) {
                return requestUrl.replaceAll(
                                "(?i)(?<=/)(?:\\d+|[a-f0-9]{24}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?=/|$)",
                                "{id}"
                );
        }
}
