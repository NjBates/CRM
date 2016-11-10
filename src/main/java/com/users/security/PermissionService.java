package com.users.security;

import static com.users.security.Role.ADMIN;
import static com.users.security.Role.USER;
import static org.springframework.security.core.context.SecurityContextHolder.getContext;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import com.users.repositories.ContactRepository;
import com.users.repositories.UserRepository;




// @Service is used for bean detection
// also to annotate classes at service layer level.
// if we use @Service in all layers, all the beans will get 
// instantiated and no issues. 
@Service

public class PermissionService {
	
	@Autowired
	private UserRepository userRepo;
	
	@Autowired
	private ContactRepository contactRepo;
	
	private UsernamePasswordAuthenticationToken getToken() {
		return (UsernamePasswordAuthenticationToken) 
getContext().getAuthentication();
}

	public boolean hasRole(Role role) {
		for (GrantedAuthority ga : getToken().getAuthorities()) {
			if (role.toString().equals(ga.getAuthority())) {
				return true;
			}
		}
		return false;
	}

	public boolean canEditUser(long userId) {
		return hasRole(ADMIN) || (hasRole(USER) && findCurrentUserId() == userId);
	}
	
	public long findCurrentUserId() {
		return userRepo.findByEmail(getToken().getName()).get(0).getId();
	}
	
	public boolean canEditContact(long contactId) {
		return hasRole(USER) && contactRepo.findByUserIdAndId(findCurrentUserId(), contactId) != null;
	}


}