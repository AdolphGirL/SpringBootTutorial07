#### 認證
- 建立一個聲明的主體過程(一般只用戶)，該主體是否可以在應用程序中使用。簡易說，可否登入系統的過程。
#### 授權
- 只確定一個主體是否允許在應用程式中，執行一個動作的過程。簡單說，登入系統後，可以做甚麼的過程。
#### spring security配置
- 官方文件
  ```
  https://docs.spring.io/spring-security/site/docs/5.3.2.BUILD-SNAPSHOT/reference/html5/#preface
  ```
- spring boot 2.x use 
  ```
  <spring-security.version>5.2.2.RELEASE</spring-security.version>
  ```
- 想在 Web 容器中使用 Spring Security 的功能，技術上來說是透過過濾器實作，具體來說，必須有個 org.springframework.web.filter.DelegatingFilterProxy 過濾器，可設定 url-pattern 為 /*，然而實際上，可以繼承 AbstractSecurityWebApplicationInitializer
  ```
  import org.springframework.security.web.context.AbstractSecurityWebApplicationInitializer;

  public class SecurityInitializer extends AbstractSecurityWebApplicationInitializer {
  }
  ```
  AbstractSecurityWebApplicationInitializer 也是 WebApplicationInitializer 的實作類別之一，會在應用程式初始化時進行 DelegatingFilterProxy 過濾器的建立與設定。
- step 1，
  - 在沒有任何配置時，默認會自動生成登入頁面/login，而在啟動過程中會有一個``Using generated security password: 35b938e0-e519-4f9e-a060-33c83d10b7d8
``，輸入後即可登入。
  - 上述的部分也可以透過yml設定默認的帳號密碼
  ```
  spring:
  security:
    user:
      name: 'admin'
      password: 'admin'
  ```
  - 舊版的spring boot要關閉默認的自動配置需在配置文件中設定
    ```
    security.basic.enabled = false
    ```
  - 新版Spring-Boot2.xx(Spring-security5.x)的則為
    - 將security包移除
    - 將org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration，不注入spring boot
     ```
     @EnableAutoConfiguration(exclude = {SecurityAutoConfiguration.class})
     ```
    - 自行實現WebSecurityConfigurerAdapter，並重寫configure(HttpSecurity http)
      ```
      @EnableWebSecurity
      public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {
          http.authorizeRequests().antMatchers("/**").permitAll();
        }
        
        /**
        * 配置userDetailsService Bean
        * 不生成默認security.user
        */
        @Bean
        @Override
        protected UserDetailsService userDetailsService() {
          return super.userDetailsService();
        }
      }
      ```
  - spring security的自訂義用戶認證配置，其核心均在上述的WebSecurityConfigurerAdapter類中。如果配置了兩個自訂義的類，就會發生``java.lang.IllegalStateException: @Order on WebSecurityConfigurers must be unique``
    ```
    protected void configure(HttpSecurity http) throws Exception {
          http.formLogin()               //  定義當需要提交表單進行用戶登入的時候，轉到的頁面
                  .and()
                  .authorizeRequests()   // 定義那些url需要被保護、那些不需要保護
                  .anyRequest()          // 任何請求，登入後可以訪問
                  .authenticated();
      }
    ```
  - 將用戶密碼設置到內存中的方式
    - 在舊版會有個問題
      ```
      @Override
      protected void configure(AuthenticationManagerBuilder auth) throws Exception {
          auth.inMemoryAuthentication().withUser("admin").password("admin").roles("ADMIN");
      }
      ```
      但在新版運行後，確定可以登入，會發生錯報``java.lang.IllegalArgumentException: There is no PasswordEncoder mapped for the id "null"``。
      ``java.lang.IllegalArgumentException: There is no PasswordEncoder mapped for the id "null"``
      ```
      spring security doc一段話...

      上面这段话的意思是，现在新的 Spring Security 中对密码的存储格式是"{id}……"。前面的 id 是加密方式，id 可以是bcrypt、sha256等，后面紧跟着是使用这种加密类型进行加密后的密码。
      因此，程序接收到内存或者数据库查询到的密码时，首先查找被{}包括起来的id，以确定后面的密码是被什么加密类型方式进行加密的，如果找不到就认为 id 是 null。这也就是为什么程序会报错：There is no PasswordEncoder mapped for the id "null"。官方文档举的例子中是各种加密方式针对同一密码加密后的存储形式，原始密码都是”password”。
      ```
    - 要想我们的项目还能够正常登陆，需要将前端传过来的密码进行某种方式加密，官方推荐的是使用bcrypt加密方式（不用用户使用相同原密码生成的密文是不同的），因此需要在 configure 方法里面指定一下
      ```
      @Override
      protected void configure(AuthenticationManagerBuilder auth) throws Exception {
          // auth.inMemoryAuthentication().withUser("admin").password("admin").roles("ADMIN");
          auth.inMemoryAuthentication()
              .passwordEncoder(new BCryptPasswordEncoder())
              .withUser("admin")
              .password(new BCryptPasswordEncoder().encode("admin"))
              .roles("ADMIN");
      }
      ```
      或者將passwordEncoder配置抽離
      ```
      @Bean
      public BCryptPasswordEncoder passwordEncoder() {
          return new BCryptPasswordEncoder();
      }

      @Override
      protected void configure(AuthenticationManagerBuilder auth) throws Exception {
          auth.inMemoryAuthentication()
              .withUser("admin")
              .password(new BCryptPasswordEncoder().encode("admin"))
              .roles("ADMIN");
      }
      ```
      還有一種方式，實現org.springframework.security.core.userdetails.UserDetailsService接口，實作loadUserByUsername(String username)方法，當用戶登入時，會調用UserDetailsService的loadUserByUsername，來驗證用戶的合法性(驗證和授權)
      ```
      这种方法为之后结合数据库或者JWT动态校验打下技术可行性基础
      @Service
      public class MyUserDetailsService implements UserDetailsService {

          @Override
          public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
              Collection<GrantedAuthority> authorities = new ArrayList<>();
              authorities.add(new SimpleGrantedAuthority("ADMIN"));
              return new User("root", new BCryptPasswordEncoder().encode("root"), authorities);
          }
        
      }

      当然，”自定义到内存”中的配置文件中的configure(AuthenticationManagerBuilder auth)配置就不需要再配置一遍了。
      
      注意：对于返回的UserDetails实现类，可以使用框架自己的 User，也可以自己实现一个 UserDetails 实现类，其中密码和权限都应该从数据库中读取出来，而不是写死在代码里。
      ```

      最佳實現，將加密類型抽離、自行實現UserDetailsService，並且注入AuthenticationManagerBuilder類別中

      ```
      @Configuration
      @EnableWebSecurity
      public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
          @Autowired
          private UserDetailsService userDetailsService;

          @Bean
          public BCryptPasswordEncoder passwordEncoder() {
              return new BCryptPasswordEncoder();
          }

          @Override
          protected void configure(AuthenticationManagerBuilder auth) throws Exception {
              auth.userDetailsService(userDetailsService)
                  .passwordEncoder(passwordEncoder());
          }
      }

      @Service
      public class MyUserDetailsService implements UserDetailsService {

          @Override
          public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
              Collection<GrantedAuthority> authorities = new ArrayList<>();
              authorities.add(new SimpleGrantedAuthority("ADMIN"));
              return new User("root", new BCryptPasswordEncoder().encode("root"), authorities);
          }
        
      }
      ```
- 自訂義安全認證
  ```
  @Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			// 需要用戶登入時，會轉到的登入頁面
			.formLogin()
			// 設置登入頁面
			.loginPage("/login")
			// 自訂義的登入接口
			.loginProcessingUrl("/user/login")
			// 登入成功後的頁面
			.defaultSuccessUrl("/home").permitAll()
			.and()
			// 設置需要驗證、與不需要驗證的頁面(目前暫時設定不需要驗證、其餘都要驗證)
			.authorizeRequests()
			// 不需要驗證的頁面
			.antMatchers("/", "/index", "/user/login").permitAll()
			// 認證後，任何請求都可以訪問
			.anyRequest().authenticated()
			// 關閉csrf
			.and().csrf().disable();
	}

  当去掉.loginProcessUrl()的配置的时候，登录完毕，浏览器会一直重定向，直至报重定向失败。因为登录驗證的 url 没有配置成所有人均可以访问，因此造成了死循环的结果。

  因此，配置了登录界面就需要配置任意可访问：.antMatchers("/user/login").permitAll()

  /user/login"，只是設定一個登入請求處理的url，不需要真的實現處理
  ，另外，form頁面的input name需要設定的與userdetils一樣

  // 靜態資源不需要驗證
  @Override
	public void configure(WebSecurity web) throws Exception {
	    web.ignoring().antMatchers("/webjars/**/*", "/**/*.css", "/**/*.js");
	}
  ```