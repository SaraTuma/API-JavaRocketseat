package br.com.danieleleao.todolist.filter;

import java.io.IOException;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import at.favre.lib.crypto.bcrypt.BCrypt;
import br.com.danieleleao.todolist.user.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class FilterTaskAuth extends OncePerRequestFilter{

    @Autowired
    private UserRepository userRepository;


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

                var servletPath = request.getServletPath();
                if(servletPath.startsWith("/tasks")){
                    
                    //pegar a autenticacao (usuario e senha)
                    var authorization = request.getHeader("Authorization");
                    var authEncoded = authorization.substring("Basic".length()).trim();
                    byte [] authDecoded = Base64.getDecoder().decode(authEncoded);
                    var authString = new String(authDecoded);
                    String [] credentials = authString.split(":");
                    String username = credentials[0];
                    String password = credentials[1];


                    System.err.println(username +" "+password);
                    //validar usuario
                    var user = this.userRepository.findByUsername(username);
                    if(user == null){
                        response.sendError(404, "Usuario nao existe!");
                    }else{
                        //Validar a senha
                        var passwordVerified = 
                        BCrypt.verifyer().verify(password.toCharArray(), 
                        user.getPassword());
                        if(passwordVerified.verified){
                            //Guardar o id do usuario na variavel request
                            request.setAttribute("idUser", user.getCodigo());
                            //continua 
                            filterChain.doFilter(request, response);
                        }else{
                            System.err.println("usuario nao autorizado!");
                            response.sendError(401, "Senha errada!");

                        }
                    }
                }
                else{
                    //continua 
                    filterChain.doFilter(request, response);
                }
                
        
    }

    
    
}
