package com.reyes.tutorial.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import com.reyes.tutorial.service.OverrideUserDetailsService;

/**
 * @EnableWebSecurity註解已隱含@Configuration，所以不用特別聲明
 * 繼承WebSecurityConfigurerAdapter，創建WebSecurityConfigurer的實例
 *
 */

@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

//  step: 1，測試取消默認登入頁面	
//	@Override
//	protected void configure(HttpSecurity http) throws Exception {
//		http.authorizeRequests().antMatchers("/**").permitAll();
//	}
//	
////	配置userDetailsService Bean
////	不生成默認security.user
//	@Bean
//	@Override
//	protected UserDetailsService userDetailsService() {
//		return super.userDetailsService();
//	}

/**
//	step: 2，測試帳號密碼，內存登入，與新版密碼編碼處理
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//		auth.inMemoryAuthentication()
////			官方推薦，使用BCrypt編碼，第一種方式處理，在內指定
//			.passwordEncoder(new BCryptPasswordEncoder())
//			.withUser("admin")
////			官方推薦，使用BCrypt編碼，第一種方式處理，在內指定
//			.password(new BCryptPasswordEncoder().encode("admin")).roles("ADMIN");
		
		auth.inMemoryAuthentication()
//			第二種方式處理，passwordEncoder抽離
			.withUser("admin")
			.password(new BCryptPasswordEncoder().encode("admin")).roles("ADMIN");
	}
	
//	第二種方式，passwordEncoder抽離
	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
**/
	
	/**
	 * 第二種方式
	 * 提供需要驗證的資料
	 */
//	@Override
//	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//		auth.inMemoryAuthentication()
////		官方推薦，使用BCrypt編碼，抽離BCryptPasswordEncoder()
//			.withUser("admin").password(new BCryptPasswordEncoder().encode("admin")).roles("ADMIN");
//	}
	
//	第三種方式，撰寫loadUserByUsername(此處配置後，就可以不用配置protected void configure(AuthenticationManagerBuilder auth)
	
//	第四種方式，最佳實現，將加密類型抽離、自行實現UserDetailsService，並且注入AuthenticationManagerBuilder類別中
	@Autowired
	private OverrideUserDetailsService overrideUserDetailsService;
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(overrideUserDetailsService).passwordEncoder(passwordEncoder());
	}
	
	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	/**
	 * 自訂義需要安全認證
	 */
	@Override
	protected void configure(HttpSecurity http) throws Exception {
//		http
//			// 需要用戶登入時，會轉到的登入頁面
//			.formLogin()
//			// 設置登入頁面
//			.loginPage("/login")
//			// 自訂義的登入接口
//			.loginProcessingUrl("/user/login")
//			// 登入成功後的頁面
//			.defaultSuccessUrl("/home").permitAll()
//			.and()
//			// 設置需要驗證、與不需要驗證的頁面(目前暫時設定不需要驗證、其餘都要驗證)
//			.authorizeRequests()
//			// 不需要驗證的頁面
//			.antMatchers("/", "/index", "/user/login").permitAll()
//			// 認證後，任何請求都可以訪問
//			.anyRequest().authenticated()
//			// 關閉csrf
//			.and().csrf().disable();
		
		http
			.authorizeRequests().antMatchers("/", "/index", "/user/login").permitAll()
				.anyRequest().authenticated()
			.and()
				.formLogin()
//				TODO 未確定loginPage vs loginProcessingUrl 
					.loginPage("/login")
					.loginProcessingUrl("/user/login")
					.defaultSuccessUrl("/home").permitAll()		// .permitAll()不加上似乎會產生ERR_TOO_MANY_REDIRECTS
			.and()
				.logout().permitAll()
			.and().csrf().disable();
	}
	
	/**
	 * 靜態資源不需要驗證(針對static目錄下)
	 * ingore是完全繞過spring security的所有filter
	 * permitall，沒有繞過spring security的所有filter
	 */
	@Override
	public void configure(WebSecurity web) throws Exception {
//		web.ignoring().antMatchers("/webjars/**/*", "/**/*.css", "/**/*.js");
		web.ignoring().antMatchers("/webjars/**", "/css/**", "/js/**");
	}
	
}
