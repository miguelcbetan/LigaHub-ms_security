package com.uc.ms_security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class MsSecurityApplication {

	public static void main(String[] args) {
		SpringApplication.run(MsSecurityApplication.class, args);
	}

}
