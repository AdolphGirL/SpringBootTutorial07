package com.reyes.tutorial.service;

import java.util.ArrayList;
import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

/**
 *	測試帳號密碼，內存登入，與新版密碼編碼處理
 *	第三種方式，撰寫loadUserByUsername(此處配置後，就可以不用配置protected void configure(AuthenticationManagerBuilder auth)
 *	第四種方式，最佳實現，將加密類型抽離、自行實現UserDetailsService，並且注入AuthenticationManagerBuilder類別中
 */

@Service
public class OverrideUserDetailsService implements UserDetailsService {

	/**
	 * 此處的user，org.springframework.security.core.userdetails.User，其中的重點在於
	 * password, username, authorities
	 * 
	 * 也可以自行創建User，但須要實現UserDetails
	 */
	@Override
	public UserDetails loadUserByUsername(String arg0) throws UsernameNotFoundException {
		Collection<GrantedAuthority> authorities = new ArrayList<>();
		authorities.add(new SimpleGrantedAuthority("ADMIN"));
		return new User("admin", new BCryptPasswordEncoder().encode("admin"), authorities);
	}

}
