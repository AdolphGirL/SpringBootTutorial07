package com.reyes.tutorial.service.impl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.reyes.tutorial.entity.UserDO;
import com.reyes.tutorial.repository.UserRepository;
import com.reyes.tutorial.service.UserDOService;

@Service
public class UserDOServiceImpl implements UserDOService {
	
	@Autowired
	private UserRepository userRepository;

	@Override
	public UserDO getUserDOByUsername(String username) {
		return userRepository.findByUsername(username);
	}

}
