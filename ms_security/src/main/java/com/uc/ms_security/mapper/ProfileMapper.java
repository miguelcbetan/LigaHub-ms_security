package com.uc.ms_security.mapper;

import com.uc.ms_security.dto.users.ProfileRequestDTO;
import com.uc.ms_security.dto.users.ProfileResponseDTO;
import com.uc.ms_security.entity.Profile;
import org.springframework.stereotype.Component;

@Component
public class ProfileMapper {

    public Profile toEntity(
            ProfileRequestDTO dto) {

        Profile profile =
                new Profile();

        profile.setPhone(
                dto.getPhone()
        );

        profile.setBirthDate(
                dto.getBirthDate()
        );

        applyPhoto(dto, profile);

        return profile;
    }

    public void updateEntity(
            ProfileRequestDTO dto,
            Profile profile) {

        profile.setPhone(
                dto.getPhone()
        );

        profile.setBirthDate(
                dto.getBirthDate()
        );

        applyPhoto(dto, profile);
    }

    public ProfileResponseDTO toResponseDTO(
            Profile profile) {

        if (profile == null) {
            return null;
        }

        return new ProfileResponseDTO(
                profile.getId(),
                profile.getPhone(),
                profile.getBirthDate(),
                profile.getPhotoUrl()
        );
    }

    /** null conserva la foto actual; "" la elimina. */
    private void applyPhoto(
            ProfileRequestDTO dto,
            Profile profile) {

        if (dto.getPhotoUrl() == null) {
            return;
        }

        profile.setPhotoUrl(
                dto.getPhotoUrl().isEmpty() ? null : dto.getPhotoUrl()
        );
    }
}
