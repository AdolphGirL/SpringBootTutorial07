
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


  