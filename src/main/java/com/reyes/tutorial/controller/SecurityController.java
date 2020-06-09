package com.reyes.tutorial.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class SecurityController {

	@GetMapping(value = {"/", "/index", "/login"})
	public String index(){
		return "login";
	}
	
	@GetMapping(value = "/home")
	public String home(){
		return "home";
	}
	
}
