package com.uc.ms_security.service;

import com.uc.ms_security.entity.ExternalIdentity;
import com.uc.ms_security.entity.User;
import com.uc.ms_security.exception.ApplicationException;
import com.uc.ms_security.exception.ErrorCase;
import com.uc.ms_security.repository.ExternalIdentityRepository;
import com.uc.ms_security.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Arrays;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Resuelve la identidad externa a un usuario interno. Nunca vincula una
 * identidad a una cuenta existente por coincidencia de correo: si el correo
 * ya pertenece a otra cuenta, el acceso se rechaza.
 */
@Service
public class ExternalIdentityService {

    private final ExternalIdentityRepository identityRepository;
    private final UserRepository userRepository;
    private final UserService userService;
    private final Set<String> unverifiedEmailProviders;

    public ExternalIdentityService(
            ExternalIdentityRepository identityRepository,
            UserRepository userRepository,
            UserService userService,
            @Value("${firebase.unverified-email-providers:}") String unverifiedProviders) {
        this.identityRepository = identityRepository;
        this.userRepository = userRepository;
        this.userService = userService;
        this.unverifiedEmailProviders = Arrays.stream(unverifiedProviders.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toSet());
    }

    /**
     * Usuario de la identidad ya registrada o, si es el primer acceso, el
     * usuario recién creado con su identidad, todo en una transacción.
     */
    @Transactional
    public User findOrCreate(FirebaseTokenVerifier.FirebaseIdentity identity) {
        Optional<ExternalIdentity> existing = identityRepository
                .findByProviderAndProviderUid(identity.provider(), identity.uid());

        if (existing.isPresent()) {
            return existing.get().getUser();
        }

        String email = normalizeEmail(identity.email());

        if (!identity.emailVerified()
                && !unverifiedEmailProviders.contains(identity.provider())) {
            throw new ApplicationException(
                    ErrorCase.INVALID_OPERATION,
                    "El proveedor no confirma que el correo esté verificado"
            );
        }

        if (userRepository.existsByEmail(email)) {
            throw new ApplicationException(
                    ErrorCase.ALREADY_EXISTS,
                    "Ya existe una cuenta con este correo. Accede con el método con el que te registraste"
            );
        }

        User user = userService.registerExternal(identity.name(), email);

        ExternalIdentity link = new ExternalIdentity();
        link.setProvider(identity.provider());
        link.setProviderUid(identity.uid());
        link.setEmail(email);
        link.setUser(user);
        identityRepository.save(link);

        return user;
    }

    private String normalizeEmail(String raw) {
        String email = raw == null ? "" : raw.trim().toLowerCase(Locale.ROOT);

        if (email.isEmpty() || email.length() > 150 || !email.contains("@")
                || email.indexOf('@') == 0 || email.endsWith("@")) {
            throw new ApplicationException(
                    ErrorCase.INVALID_OPERATION,
                    "El proveedor no entregó un correo electrónico válido. "
                            + "Verifica que tu cuenta tenga un correo público y verificado"
            );
        }
        return email;
    }
}
