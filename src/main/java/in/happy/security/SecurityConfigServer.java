package in.happy.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration
public class SecurityConfigServer {

    @Bean
    public InMemoryUserDetailsManager userDetailsManager() {
        UserDetails adminUser = User.withDefaultPasswordEncoder()
                .username("ashok")
                .password("ashok@123")
                .authorities("ROLE_ADMIN")
                .build();

        UserDetails normalUser = User.withDefaultPasswordEncoder()
                .username("raja")
                .password("raja@123")
                .authorities("ROLE_USER")
                .build();

        return new InMemoryUserDetailsManager(adminUser, normalUser);
    }

    @Bean
    public SecurityFilterChain securityconfig(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((req) -> req
                .antMatchers("/contect").permitAll()  // Allow all access to "/contact"
                .anyRequest().authenticated()             // All other requests need to be authenticated
        )
        .formLogin();                                    // Enable form login

        return http.build();
    }
}
