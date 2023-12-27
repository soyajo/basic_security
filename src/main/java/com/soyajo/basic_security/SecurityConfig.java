package com.soyajo.basic_security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.io.IOException;


import static org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher;


/**
 * https://uriu.tistory.com/435
 * 5.7 버전 이상 문법
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    @Bean
    public UserDetailsManager users() {

        UserDetails user = User.builder()
                .username("user")
                .password("{noop}1111")
                .roles("USER")
                .build();

        UserDetails sys = User.builder()
                .username("sys")
                .password("{noop}1111")
                .roles("SYS","USER")
                .build();

        UserDetails admin = User.builder()
                .username("admin")
                .password("{noop}1111")
                .roles("ADMIN", "SYS", "USER")
                .build();

        return new InMemoryUserDetailsManager( user, sys, admin );
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(CsrfConfigurer::disable)
//                .securityMatcher(matcher -> matcher
//                        .)
                .authorizeHttpRequests(
                        (authorizeRequest) -> authorizeRequest
                                .requestMatchers(antMatcher("/user")).hasRole("USER")
                                .requestMatchers(antMatcher("/admin/pay")).hasRole("ADMIN")
//                                .requestMatchers(antMatcher("/admin/**")).hasRole("SYS")
                                .requestMatchers(antMatcher("/admin/**")).hasAnyRole("ADMIN", "SYS")
                                .anyRequest().authenticated()
                )
//                .authorizeHttpRequests(authorize -> authorize
//                        .anyRequest().authenticated()
//                )
//                .httpBasic(Customizer.withDefaults())
                .formLogin(
                        (formLogin) -> formLogin
//                                .loginPage("/loginPage")
                                .defaultSuccessUrl("/")
                                .failureUrl("/login")
                                .usernameParameter("userId")
                                .passwordParameter("passWd")
                                .loginProcessingUrl("/login_proc")
                                .successHandler(new AuthenticationSuccessHandler() {
                                    @Override
                                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                                        System.out.println("authentication : " + authentication.getName());
                                        response.sendRedirect("/");
                                    }
                                })
                                .failureHandler(new AuthenticationFailureHandler() {
                                    @Override
                                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                                        System.out.println("exception  : " + exception.getMessage());
                                        response.sendRedirect("/login");
                                    }
                                })
                                .permitAll()
                )
                .logout(
                        (logout) -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/login")
                        .addLogoutHandler(new LogoutHandler() {
                            @Override
                            public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                                HttpSession session = request.getSession();
                                session.invalidate();
                            }
                        })
                        .logoutSuccessHandler(new LogoutSuccessHandler() {
                            @Override
                            public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                                response.sendRedirect("/login");
                            }
                        })
                        .deleteCookies("remember-me")
                )
                .rememberMe(
                        (rememberMe) -> rememberMe
                        .rememberMeParameter("remember") // 기본 파라미터명은 remember-me
                        .tokenValiditySeconds(3600) //default 는 14일
                        .alwaysRemember(true) // 리멤버 미 기능이 활성화되지 않아도 항상 실행
//                        .userDetailsService(new UserDetailsService() {
//                            @Override
//                            public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
//                                return null;
//                            }
//                        })
                )
                .sessionManagement((sessionManagement) -> sessionManagement
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED) // default, 스프링 시큐리티가 필요 시 생성
//                        .sessionCreationPolicy(SessionCreationPolicy.ALWAYS) // 스프링 시큐리티가 항상 생성
//                        .sessionCreationPolicy(SessionCreationPolicy.NEVER) // 스프링 시큐리티가 생성하지 않지만 이미 존재하면 사용
//                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 스프링 시큐리티가 생성하지 않고 존재해도 사용하지 않음. jwt에 사용
//                        .sessionFixation().none() // 공격자가 사용자의 쿠키를 공격자의 쿠키로 변경 후, 사용자가 로그인하면 공격자는 인증을 안받고 로그인 할 수 있다.
                        .sessionFixation().changeSessionId() // default 값, 사용자가 로그인 성공 시 쿠키 값이 변경되는 방식
                        .maximumSessions(1) // 최대 허용 가능 세션 수, -1 : 무제한 로그인 세션 허용
                        .maxSessionsPreventsLogin(false) // 동시 로그인 차단함, false : 기존 세션 만료(default)
                );

        return http.build();
    }
}
