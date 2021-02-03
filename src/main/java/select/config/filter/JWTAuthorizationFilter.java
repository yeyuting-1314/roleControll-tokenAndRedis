package select.config.filter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import redis.clients.jedis.Jedis;
import select.constants.JwtUtils;
import select.util.JedisUtil;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * @author yeyuting
 * @create 2021/1/29
 */
//验证成功后开始鉴权
public class JWTAuthorizationFilter extends BasicAuthenticationFilter {

    @Autowired
    JedisUtil jedisUtil ;

    public JWTAuthorizationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws IOException, ServletException {

        String tokenHeader = request.getHeader(JwtUtils.TOKEN_HEADER);
        //String roleHeader = request.getHeader(JwtTokenUtils.ROLE_HEADER) ;
        // 如果请求头中没有Authorization信息则直接放行了
        if (tokenHeader == null) {
            super.doFilterInternal(request, response, chain);
            return;
        }
        // 如果请求头中有token，则进行解析，并且设置认证信息  ???
        SecurityContextHolder.getContext().setAuthentication(getAuthentication(tokenHeader));
        super.doFilterInternal(request, response, chain);
    }

    // 从token中获取用户信息
    private UsernamePasswordAuthenticationToken getAuthentication(String tokenHeader) {
        String token = tokenHeader.replace(JwtUtils.TOKEN_PREFIX, "");

        //去redis里面拿token 确认redis中存在和token对应的值
        Jedis jedis = new Jedis("localhost" , 6379) ;
        String username = jedis.get(token) ;

        List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        GrantedAuthority grantedAuthority = new SimpleGrantedAuthority(jedis.get(JwtUtils.ROLE_HEADER));
        grantedAuthorities.add(grantedAuthority) ;
        if (username != null){
            return new UsernamePasswordAuthenticationToken(username, null, grantedAuthorities);
        }
        return null;
    }
}