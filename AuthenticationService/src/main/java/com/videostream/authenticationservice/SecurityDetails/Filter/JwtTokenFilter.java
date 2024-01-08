package com.videostream.authenticationservice.SecurityDetails.Filter;

import com.videostream.authenticationservice.JWT.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtTokenFilter extends OncePerRequestFilter {
    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    @Autowired
    public JwtTokenFilter(JwtService service, @Qualifier("jwtUserDetailService") UserDetailsService userService){
        this.jwtService = service;
        this.userDetailsService = userService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        //grabs the authorization header from the request
        String token = jwtService.resolveToken(request.getHeader(org.springframework.http.HttpHeaders.AUTHORIZATION));
        if(token != null && jwtService.validAuthToken(token)){
            //load jwt into user detail class
            UserDetails details = userDetailsService.loadUserByUsername(token);
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(details,null, details.getAuthorities());
            authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            logger.info("Valid Auth Token Parsed and loaded into userAccount");
        }
        filterChain.doFilter(request,response);
    }
}
