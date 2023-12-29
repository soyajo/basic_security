package com.soyajo.basic_security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;

import java.io.IOException;

import static org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher;


/**
 * https://uriu.tistory.com/435
 * 5.7 버전 이상 문법
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityAdminConfig {
    @Bean
    @Order(0)
    public SecurityFilterChain adminFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(CsrfConfigurer::disable)
//                .csrf((csrf) -> csrf
//                        .csrfTokenRepository(httpSessionCsrfTokenRepository()))
//                .securityMatcher(matcher -> matcher
//                        .)
                .authorizeHttpRequests(
                        (authorizeRequest) -> authorizeRequest
                                .requestMatchers(antMatcher("/login")).permitAll()
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
                                .loginProcessingUrl("/login")
                                .successHandler(new AuthenticationSuccessHandler() {
                                    @Override
                                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//                                        HttpSessionRequestCache requestCache = new HttpSessionRequestCache();
//                                        SavedRequest savedRequest = requestCache.getRequest(request, response);
//                                        String redirectUrl = savedRequest.getRedirectUrl();
//                                        response.sendRedirect(redirectUrl);

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
                )
                .exceptionHandling((eh) -> eh
//                        .authenticationEntryPoint(new AuthenticationEntryPoint() {
//                            @Override
//                            public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
//                                System.out.println("인증이 실패하였습니다.");
//                                response.sendRedirect("/login");
//                            }
//                        })
                        .accessDeniedHandler(new AccessDeniedHandler() {
                            @Override
                            public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
                                System.out.println("인가에 실패하였습니다.");
                                response.sendRedirect("/denied");
                            }
                        })
                );
        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
        return http.build();
    }

    @Bean
    public HttpSessionCsrfTokenRepository adminHttpSessionCsrfTokenRepository() {
        HttpSessionCsrfTokenRepository csrfRepository = new HttpSessionCsrfTokenRepository();
        // 아래와 같이 설정하지 않으면
        // 기본값은 "org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository.CSRF_TOKEN" 입니다.
        csrfRepository.setSessionAttributeName("CSRF_TOKEN");
        return csrfRepository;
    }
}
