package guru.sfg.brewery.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        return http.authorizeHttpRequests(authorizeHttpRequestCustomizer ->
                authorizeHttpRequestCustomizer.requestMatchers(antMatcher("/"),
                        antMatcher("/webjars/**"),
                        antMatcher("/resources/**"),
                        antMatcher("/login")//,
                        //antMatcher(HttpMethod.GET, "/beers/find"),
                        //antMatcher(HttpMethod.GET, "/beers/*")
                        ).permitAll()
                        .requestMatchers(HttpMethod.GET, "/beers/find").permitAll()
                        .anyRequest().authenticated())
                        .formLogin(Customizer.withDefaults())
                        .httpBasic(Customizer.withDefaults())
                        .build();
    }
}
