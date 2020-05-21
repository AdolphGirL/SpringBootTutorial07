
#### spring security
- 核心組件-SecurityContextHolder  
  用於儲存安全上下文的信息。當前操作的用戶、該用戶是否被認證、擁有權限等等，都被保存在這之中。  

  SecurityContextHolder默認使用，ThreadLocal策略來儲存認證信息，這是一種線程綁定策略。在用戶登錄時會自動綁定到當前線程，當用戶退出後，自動清除當前線程的認證訊息。  

  獲取當前用戶訊息
  ```
  Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
  if (principal instanceof UserDetails) {
      String username = ((UserDetails)principal).getUsername();
  } else {
      String username = principal.toString();
  }
  ```
  getAuthentication()，返回認證訊息；getPrincipal()，返回身分訊息；UserDetails，是針對身分訊息封裝的一個接口

- Authentication  
  原碼  
  ```
  package org.springframework.security.core;
  public interface Authentication extends Principal, Serializable {
      Collection<? extends GrantedAuthority> getAuthorities();
      Object getCredentials();
      Object getDetails();
      Object getPrincipal();
      boolean isAuthenticated();
      void setAuthenticated(boolean var1) throws IllegalArgumentException;
  }
  ```
  由此原碼可以看出  
  - 可以取得權限訊息列表-getAuthorities()
  - 密碼-getCredentials()，但基於安全性，驗證後會被移除
  - 用戶訊息細節-getDetails()
  - 身分訊息-getPrincipal()，最重要的部分，大部分情況下，返回的是UserDetails的實現類別
  - 是否通過驗證-isAuthenticated()  
  
  spring security如何驗證  
  - 用戶名稱和密碼被過濾器取得，封裝為Authentication，通常情況下是由UsernamePasswordAuthenticationToken這個類別實現
  - AuthenticationManager身分管理器負責驗證這個Authentication
  - 驗證成功後，AuthenticationManager會返回一個Authentication實例，以填充各項資料(唯獨密碼被清除)
  - 最後透過SecurityContextHolder.getContext().setAuthentication方法，將Authentication實例保存
  
- AuthenticationManager  
  因為在實際需求中，可能允許用戶使用帳號+密碼登入、EMAIL+密碼登入、手機+密碼登入等等，因此AuthenticationManager一般不會直接認證，而是AuthenticationManager接口的常用實現類ProviderManager內部維護一個List< AuthenticationProvider >列表，存放多種認證方式，默認下，只要其中一種通過，即可被認為是登入成功。如果所有的驗證都無法通過，則會拋出ProviderNotFoundException。

- DaoAuthenticationProvider
  AuthenticationProvider最常的一個實現類，也就是透過Dao(訪問資料庫層)。  
  在驗證個過程中，提交的用戶名稱和密碼，被封裝成常用的Authentication實現類UsernamePasswordAuthenticationToken，而根據用戶名稱加載用戶的責任是交給UserDetailsService，在DaoAuthenticationProvider中對應的方法就是retrieveUser，雖然有兩個參數，但是retrieveUser只有第一個參數起作用，返回一個UserDetails。最後需要將UsernamePasswordAuthenticationToken和UserDetails的密碼比對，這項工作交給additionalAuthenticationChecks方法完成，如果沒有異常，則比對成功。PasswordEncoder 和 SaltSource則為密碼加密的概念。

- UserDetails、UserDetailsService
  UserDetails和Authentication接口很像，但Authentication的getCredentials()，保存用戶提交的密碼、UserDetails保存的是用戶正確的密碼。其實就是DaoAuthenticationProvider中的retrieveUser會根據Authentication內的帳號，取得一個該帳號user的資料封裝在UserDetails，然後回傳；再經由additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthentication)，來進行比對。  

  UserDetailsService和AuthenticationProvider的職責不相同，UserDetailsService只負責特定的地方(通常是資料庫)去加載用戶資料封裝為UserDetails。UserDetailsService常見的實現類JdbcDaoImpl、InMemoryUserDetailsManager。。也可以自行實現。

#### 配置
- 基本情況  
  在新版的spring security，沒有任何配置的情況下或默認產稱一個login頁面，而在啟動的過程中，會有有一個``Using generated security password: 35b938e0-e519-4f9e-a060-33c83d10b7d8``，輸入後即可登入；另外也可以透過yml檔設定默認的帳號密碼。  
  ```
  spring:
    security:
      user:
        name: 'admin'
        password: 'admin'
  ```
- 新版的spring security針對於密碼的部分，都需要加密處理，官方推薦使用bcrypt加密方式，new BCryptPasswordEncoder()
- @EnableWebSecurity(@EnableWebSecurity註解已隱含@Configuration，所以不用特別聲明)，聲明後，集成了spring security對web的支持；
- configure(HttpSecurity)，可以定義那些url需要被攔截，需要登入等等設定
- configure(WebSecurity web)，設定靜態資源不需要驗證(針對static目錄下)，完全繞過spring security的所有filter；ingore是完全繞過spring security的所有filter，permitall，沒有繞過spring security的所有filter
- configure(AuthenticationManagerBuilder auth)，登入方式設定。
- 測試範例，內存中建立一使用者  
  ```
  @Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.inMemoryAuthentication()
    // 官方推薦，使用BCrypt編碼，抽離BCryptPasswordEncoder()
			.withUser("admin").password(new BCryptPasswordEncoder().encode("admin")).roles("ADMIN");
	}

  @Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
  ```
- 默認測試，使用者提交username、password表單，在spring security，當沒有配置登入頁面時，會自動升成一個登入頁面。 
- 驗證失敗會/login?error、登出會login?logout

#### 核心配置說明
- WebSecurityConfigurerAdapter，可以選擇性覆蓋一些想要實現的設定  
  ```
  @Configuration
  @EnableWebSecurity
  public class CustomWebSecurityConfig extends WebSecurityConfigurerAdapter {
    
      @Override
      protected void configure(HttpSecurity http) throws Exception {
          http
              .authorizeRequests()
                  .antMatchers("/resources/**", "/signup", "/about").permitAll()
                  .antMatchers("/admin/**").hasRole("ADMIN")
                  .antMatchers("/db/**").access("hasRole('ADMIN') and hasRole('DBA')")
                  .anyRequest().authenticated()
                  .and()
              .formLogin()
                  .usernameParameter("username")
                  .passwordParameter("password")
                  .failureForwardUrl("/login?error")
                  .loginPage("/login")
                  .permitAll()
                  .and()
              .logout()
                  .logoutUrl("/logout")
                  .logoutSuccessUrl("/index")
                  .permitAll()
                  .and()
              .httpBasic()
                  .disable();
      }
  }
  ```
  authorizeRequests()，配置路徑攔截、表明訪問的權限等  
  formLogin()，對應表單登入的配置  
  logout()，對應登出的相關配置  
  httpBasic()，可以配置basic登入

- @EnableWebSecurity，透過import引入外部的配置類(如WebSecurityConfiguration)

#### 過濾器說明
- Spring Security使用了springSecurityFillterChian(在WebSecurityConfiguration.class)，作為安全過濾的入口
- SecurityContextPersistenceFilter(org.springframework.security.web.context.SecurityContextPersistenceFilter)，用戶訊息會經過此filter進而保存到SecurityContextHolder。請求來臨時創建SecurityContext安全上下文，請求結束時，清空SecurityContextHolder
- UsernamePasswordAuthenticationFilter，org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter；一些代碼至於AbstractAuthenticationProcessingFilter中；流程上調用authenticationManager進行驗證，驗證成功執行successfulAuthentication，驗證失敗執行unsuccessfulAuthentication，而不管驗證成功或失敗，都會經由轉發或者重新定位處理請求，交由AuthenticationSuccessHandler 和 AuthenticationFailureHandler封裝處理
- AnonymousAuthenticationFilter，匿名任制過濾器，針對未登入者，有自己的一套流程
- ExceptionTranslationFilter，異常轉換過濾器。本身不處理異常，交由別的處理，只做轉換動作；一般處理兩大異常AccessDeniedException(訪問異常)和AuthenticationException(認證異常)。
- FilterSecurityInterceptor，資源角色的檢核。
  
#### 原碼認證過程  
- http://www.spring4all.com/article/439  

#### 源碼授權過程，幾個重要的filter
- org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter，最先遇到的filter；會先調用父類AbstractAuthenticationProcessingFilter.doFilter()，再調用自行實現的attemptAuthentication，attemptAuthentication驗證部分源碼  
  ```
  if (postOnly && !request.getMethod().equals("POST")) {
		throw new AuthenticationServiceException(
				"Authentication method not supported: " + request.getMethod());
	}

  取出request資料
  String username = obtainUsername(request);
	String password = obtainPassword(request);

  封裝為UsernamePasswordAuthenticationToken
  UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(
				username, password);

  最後返回透過AuthenticationManager的實現類驗證後，返回驗證結果，給父類
  return this.getAuthenticationManager().authenticate(authRequest);
  ```
- org.springframework.security.web.authentication.AnonymousAuthenticationFilter，當在其前面的過濾器都沒有成功時，spring security則會在當前的SecurityContextHolder中添加一個Authenticaiton的匿名實現類別AnonymousAuthenticationToken。用戶名為anonymousUser、授權為ROLE_ANONYMOUS
- org.springframework.security.web.access.ExceptionTranslationFilter，異常處理過濾器，主要是用來處理系統在認證授權過程中拋出的異常，主要處理AuthenticationException 和 AccessDeniedException
- org.springframework.security.web.access.intercept.FilterSecurityInterceptor，最後一個filter，處理真正請求；其會調用``InterceptorStatusToken token = super.beforeInvocation(fi);``中的beforeInvocation，該過程會再去調用AccessDecisionManager來驗證當前的用戶使否有授權動作，可以訪問目前的資源。在beforeInvocation源碼中有一段  
```
this.accessDecisionManager.decide(authenticated, object, attributes);
```
authenticated，表示當前認證的Authentication  
object，表示為當前的請求(/xxx)  
attributes，就是當前的資源去匹配我們定義的匹配規則  
- AccessDecisionManager授權。