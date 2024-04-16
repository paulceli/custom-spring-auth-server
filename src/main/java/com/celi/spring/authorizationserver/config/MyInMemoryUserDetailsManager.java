package com.celi.spring.authorizationserver.config;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import java.util.Collection;

public class MyInMemoryUserDetailsManager extends InMemoryUserDetailsManager {

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        String password = "password";
        boolean isEnabled = true;
        boolean isAccountNonExpired = true;
        boolean isCredentialsNonExpired = true;
        boolean isAccountNonLocked = true;
        Collection<GrantedAuthority> grantedAuthority = AuthorityUtils.createAuthorityList("USER");

        return new User(username, password, isEnabled,
                isAccountNonExpired, isCredentialsNonExpired,
                isAccountNonLocked, grantedAuthority);
    }
}
