package com.users.security;

import static org.springframework.security.core.context.SecurityContextHolder.getContext;
import static com.users.security.Role.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import com.users.repositories.ContactRepository;
import com.users.repositories.UserRepository;

@Service
public class PermissionService {

	@Autowired
	private UserRepository userRepo;

	@Autowired
	private ContactRepository contactRepo;

	private UsernamePasswordAuthenticationToken getToken() {
		return (UsernamePasswordAuthenticationToken) getContext().getAuthentication();
	}

	public boolean hasRole(Role role) {
		for (GrantedAuthority ga : getToken().getAuthorities()) {
			if (role.toString().equals(ga.getAuthority())) {
				return true;
			}
		}
		return false;
	}

	public long findCurrentUserId() {
		return userRepo.findByEmail(getToken().getName()).get(0).getId();
	}

	public boolean canAccessUser(long userId) {
		return hasRole(ROLE_ADMIN) || (hasRole(ROLE_USER) && findCurrentUserId() == userId);
	}

	public boolean canEditContact(long contactId) {
		return hasRole(ROLE_USER) && contactRepo.findByUserIdAndId(findCurrentUserId(), contactId) != null;
	}

}