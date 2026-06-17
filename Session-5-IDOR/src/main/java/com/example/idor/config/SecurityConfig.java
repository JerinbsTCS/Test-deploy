package com.example.idor.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/h2-console/**").permitAll()
                .requestMatchers("/api/public/**").permitAll()
                .anyRequest().authenticated()
            )
            .httpBasic(withDefaults())
            .headers(headers -> headers.frameOptions(frame -> frame.disable()));

        return http.build();
    }

    /**
     * Pre-configured users for the lab.
     * Each customer logs in with their own credentials but the vulnerable API
     * lets them access ANY customer's orders/invoices by changing the ID.
     */
    @Bean
    public UserDetailsService userDetailsService(PasswordEncoder encoder) {
        var manager = new InMemoryUserDetailsManager();

        // Customers
        manager.createUser(User.builder()
                .username("john").password(encoder.encode("john123"))
                .roles("CUSTOMER").build());
        manager.createUser(User.builder()
                .username("sarah").password(encoder.encode("sarah123"))
                .roles("CUSTOMER").build());
        manager.createUser(User.builder()
                .username("mike").password(encoder.encode("mike123"))
                .roles("CUSTOMER").build());
        manager.createUser(User.builder()
                .username("emma").password(encoder.encode("emma123"))
                .roles("CUSTOMER").build());

        // Support staff
        manager.createUser(User.builder()
                .username("support").password(encoder.encode("support123"))
                .roles("SUPPORT").build());

        // Admin (has the CTF flag hidden in an order)
        manager.createUser(User.builder()
                .username("admin").password(encoder.encode("admin123"))
                .roles("ADMIN").build());

        return manager;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
