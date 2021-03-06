package com.reyes.tutorial.service;

import java.util.ArrayList;
import java.util.Collection;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.reyes.tutorial.entity.UserDO;

/**
 *	測試帳號密碼，內存登入，與新版密碼編碼處理
 *	第三種方式，撰寫loadUserByUsername(此處配置後，就可以不用配置protected void configure(AuthenticationManagerBuilder auth)
 *	第四種方式，最佳實現，將加密類型抽離、自行實現UserDetailsService，並且注入AuthenticationManagerBuilder類別中
 *
 *	AbstractUserDetailsAuthenticationProvider，retrieveUser方法的實現類(其中之一DaoAuthenticationProvider)會使用到loadUserByUsername
 *  DaoAuthenticationProvider，在生成物件時會注入PasswordEncoder；最後在additionalAuthenticationChecks時就會將封裝好的前端資料的密碼編碼，再和資料庫的比對
 *
 */

@Service
public class OverrideUserDetailsService implements UserDetailsService {
	
	@Autowired
	private UserDOService userDOService;
	
	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;

	/**
	 * 此處的user，org.springframework.security.core.userdetails.User，其中的重點在於
	 * password, username, authorities
	 * 
	 * 也可以自行創建User，但須要實現UserDetails
	 */
	
	/**
	 * 第三種方式，記得要建立一個passwordEncoder
	 */
//	@Override
//	public UserDetails loadUserByUsername(String arg0) throws UsernameNotFoundException {
//		UserDO userDO = userDOService.getUserDOByUsername(arg0);
//		if(userDO == null){
//			throw new UsernameNotFoundException("用戶不存在");
//		}
//		
////		System.out.println(bCryptPasswordEncoder.encode(userDO.getPassword()));
//		
//		Collection<GrantedAuthority> authorities = new ArrayList<>();
//		authorities.add(new SimpleGrantedAuthority("ADMIN"));
//		return new User(userDO.getUsername(), userDO.getPassword(), authorities);
//	}
	
	/**
	 * 第四種方式
	 */
	@Override
	public UserDetails loadUserByUsername(String arg0) throws UsernameNotFoundException {
		UserDO userDO = userDOService.getUserDOByUsername(arg0);
		if(userDO == null){
			throw new UsernameNotFoundException("用戶不存在");
		}
		
		Collection<GrantedAuthority> authorities = new ArrayList<>();
		authorities.add(new SimpleGrantedAuthority("ADMIN"));
		return new User(userDO.getUsername(), userDO.getPassword(), authorities);
	}
}
