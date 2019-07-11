package br.com.treinaweb.twgerenciadortarefas;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter{
	
	@Autowired
	private BCryptPasswordEncoder passwordEncoder;
	
	// faz a conexao com banco de dado , para securitury acessa os dados
	@Autowired
	private DataSource dataSource;
	
	/// serve para trazer a sql usuario
	/// uso o value para configurar da Application.properties 
	@Value("${spring.queries.users-query}")
	private String userQuery;
	
	/// serve para trazer a sql do perfil
	// uso o value para configurar da Application.properties 
	@Value("${spring.queries.roles-query}")
	private String roleQuery;
	
	
	// indica qual o datasource , como  localiza usuario e perfil. usuado para fazer para autenticar
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth
		.jdbcAuthentication()
		.usersByUsernameQuery(userQuery)
		.authoritiesByUsernameQuery(roleQuery)
		.dataSource(dataSource)
		.passwordEncoder(passwordEncoder);
		
	}
	
	// configura os aspectos da aplicação , os acesso das url , processo para autenticar
	@Override
	protected void configure(HttpSecurity http) throws Exception{
		
		http
		.authorizeRequests()
		.antMatchers("/login").permitAll()
		.antMatchers("/registration").permitAll()
		.anyRequest()
		.authenticated()
		.and().csrf().disable()
		.formLogin()
		.loginPage("/login").failureUrl("/login?error=true").defaultSuccessUrl("/")
		.usernameParameter("email").passwordParameter("senha")
		.and().logout()
		.logoutRequestMatcher(new AntPathRequestMatcher("/logout")).logoutSuccessUrl("/login");
		
	}
	
	
	// configure quais paginas todos podem tem acesso
	@Override
	public  void configure(WebSecurity web) throws Exception{
		web.ignoring().antMatchers("/webjars/**");
		
	}
	

}
