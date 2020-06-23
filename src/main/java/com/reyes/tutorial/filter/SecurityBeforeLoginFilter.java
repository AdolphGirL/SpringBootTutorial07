package com.reyes.tutorial.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.springframework.web.filter.GenericFilterBean;

/***
 * spring security自訂義filter
 * 需要繼承GenericFilterBean 
 *
 */
public class SecurityBeforeLoginFilter extends GenericFilterBean {
	
	/**
	 * 目前沒有任何實現，只用log紀錄
	 */
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		logger.info("[SpringBootTutorial07]-[SecurityBeforeLoginFilter]-[" + request + "]");
		
		chain.doFilter(request, response);
	}

}
