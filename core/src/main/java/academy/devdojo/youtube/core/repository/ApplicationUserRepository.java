package academy.devdojo.youtube.core.repository;


import academy.devdojo.youtube.core.model.ApplicationUser;
import org.springframework.data.repository.PagingAndSortingRepository;

import java.util.Optional;

public interface ApplicationUserRepository extends PagingAndSortingRepository<ApplicationUser, Long> {
    Optional<ApplicationUser> findByUsername(String username);
}
