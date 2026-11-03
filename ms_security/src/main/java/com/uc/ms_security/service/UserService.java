package com.uc.ms_security.service;

import com.uc.ms_security.dto.roles.AssignRoleRequestDTO;
import com.uc.ms_security.dto.users.*;
import com.uc.ms_security.entity.AuthMethod;
import com.uc.ms_security.entity.Role;
import com.uc.ms_security.entity.User;
import com.uc.ms_security.exception.ApplicationException;
import com.uc.ms_security.exception.ErrorCase;
import com.uc.ms_security.mapper.UserMapper;
import com.uc.ms_security.repository.RoleRepository;
import com.uc.ms_security.repository.UserRepository;
import lombok.RequiredArgsConstructor;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;

    private final UserMapper userMapper;

    private final PasswordEncoder passwordEncoder;

    private final RoleRepository roleRepository;

    private final UserRoleService userRoleService;

    /** Rol que reciben los usuarios que se registran por su cuenta (nombre tal como está en la BD). */
    private static final String INITIAL_ROLE_NAME = "USUARIO INICIAL";

    /**
     * Autorregistro: crea el usuario y le asigna el rol inicial en una sola
     * transacción. Si el rol no existe no se crea el usuario.
     */
    @Transactional
    public UserResponseDTO register(CreateUserDTO dto) {
        Role initialRole = findInitialRole();

        UserResponseDTO created = create(dto);

        assignRole(created.getId(), initialRole);

        return created;
    }

    /**
     * Alta de un usuario autenticado por un proveedor externo. Recibe las
     * mismas reglas que el autorregistro (rol inicial, misma transacción) y
     * ningún privilegio adicional. La contraseña es un valor aleatorio que
     * nadie conoce: la cuenta solo es accesible por su proveedor.
     */
    @Transactional
    public User registerExternal(String name, String email) {
        Role initialRole = findInitialRole();

        byte[] secret = new byte[32];
        new SecureRandom().nextBytes(secret);

        User user = new User();
        user.setName(displayName(name, email));
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(
                Base64.getUrlEncoder().withoutPadding().encodeToString(secret)));
        user.setAuthMethod(AuthMethod.OAUTH);
        User saved = userRepository.save(user);

        assignRole(saved.getId(), initialRole);

        return saved;
    }

    private Role findInitialRole() {
        return roleRepository
                .findByNameIgnoreCase(INITIAL_ROLE_NAME)
                .orElseThrow(() -> new ApplicationException(
                        ErrorCase.NOT_FOUND,
                        "Rol inicial no encontrado: " + INITIAL_ROLE_NAME
                ));
    }

    private void assignRole(Long userId, Role role) {
        AssignRoleRequestDTO assignment = new AssignRoleRequestDTO();
        assignment.setUserId(userId);
        assignment.setRoleId(role.getId());
        userRoleService.assign(assignment);
    }

    /** El nombre del proveedor puede faltar o no cumplir la longitud del modelo (2-100). */
    private String displayName(String name, String email) {
        String candidate = name == null ? "" : name.trim();
        if (candidate.length() < 2) {
            candidate = email.substring(0, email.indexOf('@'));
        }
        if (candidate.length() < 2) {
            candidate = "Usuario";
        }
        return candidate.length() > 100 ? candidate.substring(0, 100) : candidate;
    }

    public UserResponseDTO create(CreateUserDTO dto) {
        if (userRepository.existsByEmail(dto.getEmail())) {
            throw new ApplicationException(
                ErrorCase.ALREADY_EXISTS,
                    "Ya existe un usuario con este email"
            );
        }
        String encodedPassword = passwordEncoder.encode(dto.getPassword());
        User user = userMapper.toEntity(dto, encodedPassword);
        User savedUser = userRepository.save(user);
        return userMapper.toResponseDTO(savedUser);
    }

    public List<UserResponseDTO> findAll() {
        List<User> users =userRepository.findAll();
        return userMapper.toResponseDTOList(users);
    }
    private User findUser(Long id) {
        return userRepository.findById(id)
            .orElseThrow(() -> new ApplicationException(
                ErrorCase.NOT_FOUND,
                "Usuario no encontrado con id: " + id
            ));
    }

    public UserResponseDTO findById(Long id) {
        User user = findUser(id);
        return userMapper.toResponseDTO(user);
    }

    public UserDetailResponseDTO findByIdAndProfile(Long id) {
        User user =userRepository
                        .findWithProfileById(id)
                        .orElseThrow(
                            () -> new ApplicationException(
                                ErrorCase.NOT_FOUND,
                                "Usuario no encontrado con id: " + id
                                )
                        );

        return userMapper.toDetailResponseDTO(user);
    }

    public UserResponseDTO update(Long id, UpdateUserDTO dto) {
        User user = findUser(id);
        if (userRepository.existsByEmailAndIdNot(dto.getEmail(), id)) {
            throw new ApplicationException(
                ErrorCase.ALREADY_EXISTS,
                    "El email pertenece a otro usuario"
            );
        }
        userMapper.updateBasicData(dto, user);

        if (dto.getPassword() != null && !dto.getPassword().isBlank()) {
            user.setPassword(passwordEncoder.encode(dto.getPassword()));
        }

        User updatedUser = userRepository.save(user);
        return userMapper.toResponseDTO(updatedUser);
    }
    public UserResponseDTO updateStatus(Long id, UpdateUserStatusDTO dto) {
        User user = findUser(id);
        user.setActive(dto.getActive());
        return userMapper.toResponseDTO(userRepository.save(user));
    }
    public void delete(Long id) {
        User user = findUser(id);
        userRepository.delete(user);
    }
    public UserSessionsResponseDTO findByIdAndSessions(Long id) {
        User user = userRepository
                .findWithSessionsById(id)
                .orElseThrow(
                    () -> new ApplicationException(
                        ErrorCase.NOT_FOUND,
                        "Usuario no encontrado con id: " + id
                        )
                );

        return userMapper.toSessionsResponseDTO(user);
    }

    public UserRolesResponseDTO findByIdAndRoles(Long id) {
        User user = userRepository
                .findWithRolesById(id)
                .orElseThrow(
                    () -> new ApplicationException(
                        ErrorCase.NOT_FOUND,
                        "Usuario no encontrado con id: " + id
                        )
                );

        return userMapper.toRolesResponseDTO(user);
    }
}