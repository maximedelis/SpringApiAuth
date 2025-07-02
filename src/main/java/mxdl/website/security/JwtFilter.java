package mxdl.website.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import mxdl.website.models.ErrorMessageResponse;
import mxdl.website.models.User;
import mxdl.website.services.JwtService;
import mxdl.website.services.UserService;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.UUID;

public class JwtFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserService userService;
    private final RequestAttributeSecurityContextRepository requestAttributeSecurityContextRepository;

    public JwtFilter(JwtService jwtService,  UserService userService,  RequestAttributeSecurityContextRepository requestAttributeSecurityContextRepository) {
        this.jwtService = jwtService;
        this.userService = userService;
        this.requestAttributeSecurityContextRepository = requestAttributeSecurityContextRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String path = request.getServletPath();
        if (path.equals("/api/auth/login") || path.equals("/api/auth/register")) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            String token = jwtService.getJwtFromRequest(request);

            if (token == null) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.setContentType("application/json");
                ObjectMapper objectMapper = new ObjectMapper();
                String jsonResponse = objectMapper.writeValueAsString(new ErrorMessageResponse("Unauthorized"));
                response.getWriter().write(jsonResponse);
                return;
            }

            if (jwtService.isExpired(token)) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.setContentType("application/json");
                ObjectMapper objectMapper = new ObjectMapper();
                String jsonResponse = objectMapper.writeValueAsString(new ErrorMessageResponse("Unauthorized"));
                response.getWriter().write(jsonResponse);
                return;
            }

            if (jwtService.validateToken(token)) {
                UUID userId = jwtService.getIdFromToken(token);
                User user = userService.loadUserById(userId);
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);

                this.requestAttributeSecurityContextRepository.saveContext(SecurityContextHolder.getContext(), request, response);

                filterChain.doFilter(request, response);
            }

            else {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.setContentType("application/json");
                ObjectMapper objectMapper = new ObjectMapper();
                String jsonResponse = objectMapper.writeValueAsString(new ErrorMessageResponse("Unauthorized"));
                response.getWriter().write(jsonResponse);
            }

        } catch (Exception e) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            ObjectMapper objectMapper = new ObjectMapper();
            String jsonResponse = objectMapper.writeValueAsString(new ErrorMessageResponse("Unauthorized"));
            response.getWriter().write(jsonResponse);
        }

    }

}

