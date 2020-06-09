package com.reyes.tutorial.repository;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import com.reyes.tutorial.entity.UserDO;

@Repository
public interface UserRepository extends CrudRepository<UserDO, Long> {
	
	public UserDO findByUsername(String username);
	
}
