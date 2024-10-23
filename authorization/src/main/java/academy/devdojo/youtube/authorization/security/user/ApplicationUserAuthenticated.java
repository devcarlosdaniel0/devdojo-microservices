package academy.devdojo.youtube.authorization.security.user;

import academy.devdojo.youtube.core.model.ApplicationUser;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

import static org.springframework.security.core.authority.AuthorityUtils.commaSeparatedStringToAuthorityList;

@RequiredArgsConstructor
public class ApplicationUserAuthenticated implements UserDetails {
    private final ApplicationUser applicationUser;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return commaSeparatedStringToAuthorityList("ROLE_" + applicationUser.getRole());
    }

    @Override
    public String getPassword() {
        return applicationUser.getPassword();
    }

    @Override
    public String getUsername() {
        return applicationUser.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
