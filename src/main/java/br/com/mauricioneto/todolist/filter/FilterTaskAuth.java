package br.com.mauricioneto.todolist.filter;


import at.favre.lib.crypto.bcrypt.BCrypt;
import br.com.mauricioneto.todolist.user.IUserRepository;
import br.com.mauricioneto.todolist.user.UserModel;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Base64;

@Component
public class FilterTaskAuth extends OncePerRequestFilter {

    @Autowired
    private IUserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String servletPath = request.getServletPath();

        if(servletPath.startsWith("/tasks")) {

            String authorization = request.getHeader("Authorization");

            String authEncoded = authorization.substring("Basic".length()).trim();

            byte[] authDecode = Base64.getDecoder().decode(authEncoded);

            String authString = new String(authDecode);

            String[] credentials = authString.split(":");
            String username = credentials[0];
            String password = credentials[1];

            UserModel user = userRepository.findByUsername(username);
            verifyUser(request, response, filterChain, password, user);

        } else {
            filterChain.doFilter(request, response);
        }

    }

    private void verifyUser(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain, String password, UserModel user)
            throws IOException, ServletException {
        if ( user == null) {
           response.sendError(401);
        } else {
          BCrypt.Result passwordVerify =  BCrypt.verifyer().verify(password.toCharArray(), user.getPassword());
          this.verifyPassword(passwordVerify, user, request, response, filterChain);
        }
    }

    private void verifyPassword(BCrypt.Result password, UserModel user, HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        if (password.verified) {
            request.setAttribute("idUser", user.getId());
            filterChain.doFilter(request, response);
        } else {
            response.sendError(401);
        }
    }

}
