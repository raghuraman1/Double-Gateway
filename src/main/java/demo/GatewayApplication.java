package demo;

import java.security.Principal;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.cloud.netflix.zuul.EnableZuulProxy;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.JdbcUserDetailsManagerConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.servlet.configuration.EnableWebMvcSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.session.jdbc.config.annotation.web.http.EnableJdbcHttpSession;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@SpringBootApplication
@Controller
@EnableZuulProxy
@EnableWebMvcSecurity
@EnableJdbcHttpSession
public class GatewayApplication {

	@RequestMapping("/user")
	@ResponseBody
	public Map<String, Object> user(Principal user) {
		Map<String, Object> map = new LinkedHashMap<String, Object>();
		map.put("name", user.getName());
		map.put("roles", AuthorityUtils.authorityListToSet(((Authentication) user)
				.getAuthorities()));
		return map;
	}

	@RequestMapping("/login")
	public String login() {
		return "forward:/";
	}

	public static void main(String[] args) {
		SpringApplication.run(GatewayApplication.class, args);
	}
	
	@Configuration
	@Order(SecurityProperties.ACCESS_OVERRIDE_ORDER)
	protected static class SecurityConfiguration extends WebSecurityConfigurerAdapter {
		 @Autowired
		 DataSource dataSource;
		@Autowired
		public void globalUserDetails(AuthenticationManagerBuilder auth) throws Exception {
			
			// @formatter:off
//			auth.inMemoryAuthentication()
//				.withUser("user").password("password").roles("USER")
//			.and()
//				.withUser("admin").password("admin").roles("USER", "ADMIN","WRITER"."READER")
//			.and()
//				.withUser("audit").password("audit").roles("USER", "ADMIN");
			
//// @formatter:on
			 JdbcUserDetailsManagerConfigurer<AuthenticationManagerBuilder> usersByUsernameQuery = auth.jdbcAuthentication().dataSource(dataSource)
			  .usersByUsernameQuery(
			   "select username,password, enabled from users where username=?");
			 usersByUsernameQuery
		  .authoritiesByUsernameQuery(
			   "select username, role from users where username=?");
		}
	
		protected void configure(HttpSecurity http) throws Exception {
			
			// @formatter:off
			http
				.httpBasic().and()
				.logout().and()
				.authorizeRequests()
					.antMatchers("/index.html", "/login","/ui3/**","/ui2/**","/ui1/**","/resource/**", "/").permitAll()
					.anyRequest().authenticated()
					.and()
				.csrf()
					.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
			// @formatter:on
		
	      	}
	}

}
