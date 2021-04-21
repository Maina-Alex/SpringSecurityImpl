package com.avania.Security;

import com.avania.Auth.ApplicationUserService;
import com.avania.Jwt.JwtConfig;
import com.avania.Jwt.JwtTokenVerifier;
import com.avania.Jwt.JwtUsernameAndPasswordAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.crypto.SecretKey;

import static com.avania.Security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;
    private final ApplicationUserService applicationUserService;
    private final SecretKey secretKey;
    private  final JwtConfig jwtConfig;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder, ApplicationUserService applicationUserService, SecretKey secretKey, JwtConfig jwtConfig) {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserService = applicationUserService;
        this.secretKey = secretKey;
        this.jwtConfig = jwtConfig;
    }
    //                .antMatchers(HttpMethod.DELETE,"management/api/**").hasAuthority(COURSE_WRITE.name())
//                .antMatchers(HttpMethod.POST,"management/api/**").hasAuthority(COURSE_WRITE.name())
//                .antMatchers(HttpMethod.PUT,"management/api/**").hasAuthority(COURSE_WRITE.name())
//                .antMatchers(HttpMethod.DELETE,"management/api/**").hasAnyRole(ADMIN.name(),ADMIN_TRAINEE.name())
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
              //  .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
              //  .and()
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(), jwtConfig, secretKey))
                .addFilterAfter(new JwtTokenVerifier(secretKey, jwtConfig),JwtUsernameAndPasswordAuthenticationFilter.class)
                .authorizeRequests()
                .antMatchers("/","index","/css/*","/js/*")
                .permitAll()
                .antMatchers("/api/**").hasRole(STUDENT.name())
                .anyRequest()
                .authenticated();
//
//
//
//                .and()
//                .formLogin()
//                .loginPage("/login").permitAll()
//                .defaultSuccessUrl("/courses",true)
//                .and()
//                .rememberMe()
//                .tokenValiditySeconds((int)TimeUnit.DAYS.toSeconds(21))
//                .key("springsecureket1234567")
//                .and()
//                .logout()
//                .logoutUrl("/logout")
//                .clearAuthentication(true)
//                .invalidateHttpSession(true)
//                .deleteCookies("JSESSIONID","remember-me")
//                .logoutSuccessUrl("/login");
                //.httpBasic();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(daoAuthenticationProvider());
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(){
        DaoAuthenticationProvider provider=new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(applicationUserService);
        return provider;
    }


//    @Override
//    @Bean
//    protected UserDetailsService userDetailsService() {
//        UserDetails annasmithUser = User.builder()
//                .username("annasmith")
//                .password(passwordEncoder.encode("password"))
//               // .roles(STUDENT.name()) //ROLE_STUDENT
//                .authorities(STUDENT.getGrantedAuthorities())
//                .build();


//
//        UserDetails lindaUser = User.builder()
//                .username("linda")
//                .password(passwordEncoder.encode("password123"))
//                //.roles(ADMIN.name()) //ROLE_ADMIN
//                .authorities(ADMIN.getGrantedAuthorities())
//                .build();

//        UserDetails tomUser = User.builder()
//                .username("tom")
//                .password(passwordEncoder.encode("password12"))
//                //.roles(ADMIN_TRAINEE.name()) //ROLE_ADMIN_TRAINEE
//                .authorities(ADMIN_TRAINEE.getGrantedAuthorities())
//                .build();

//      return  new InMemoryUserDetailsManager(
//              annasmithUser,
//              lindaUser,
//              tomUser
//      );
//    }
}
