package com.example.auth.demo.config;

import java.io.IOException;
import java.util.HashMap;
import java.util.Set;

import javax.annotation.Resource;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.alibaba.fastjson.JSON;
import com.example.auth.demo.domain.auth.UserDetail;
import com.example.auth.demo.utils.GenericResponse;
import com.example.auth.demo.utils.JwtUtils;
import com.example.auth.demo.utils.RedisUtil;
import com.example.auth.demo.utils.ServiceError;

/**
 * token校验
 * @author: JoeTao
 * createAt: 2018/9/14
 */
@Component
public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {

    @Value("${jwt.header}")
    private String token_header;
    
    @Value("${token.expirationMilliSeconds}")
    private long expirationMilliSeconds;

    @Resource
    private JwtUtils jwtUtils;
    
    @Resource
    RedisUtil redisUtil;

    /*@Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        String auth_token = request.getHeader(this.token_header);
        final String auth_token_start = "Bearer ";
        if (StringUtils.isNotEmpty(auth_token) && auth_token.startsWith(auth_token_start)) {
            auth_token = auth_token.substring(auth_token_start.length());
        } else {
            // 不按规范,不允许通过验证
            auth_token = null;
        }

        String username = jwtUtils.getUsernameFromToken(auth_token);

        logger.info(String.format("Checking authentication for userDetail %s.", username));

        if (jwtUtils.containToken(username, auth_token) && username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetail userDetail = jwtUtils.getUserFromToken(auth_token);
            if (jwtUtils.validateToken(auth_token, userDetail)) {
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetail, null, userDetail.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                logger.info(String.format("Authenticated userDetail %s, setting security context", username));
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }
        chain.doFilter(request, response);
    }*/
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        String auth_token = request.getHeader(this.token_header);
        final String auth_token_start = "Bearer ";
        if (StringUtils.isNotEmpty(auth_token) && auth_token.startsWith(auth_token_start)) {
            auth_token = auth_token.substring(auth_token_start.length());
        } else {
            // 不按规范,不允许通过验证
            auth_token = null;
        }
        String username = jwtUtils.getUsernameFromToken(auth_token);
        logger.info(String.format("Checking authentication for userDetail %s.", username));

        if (jwtUtils.containToken(username, auth_token) && username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
        	//获取redis中的token信息
            if (!redisUtil.hasKey(auth_token)){
                //token 不存在 返回错误信息
                response.getWriter().write(JSON.toJSONString(GenericResponse.response(ServiceError.GLOBAL_ERR_NO_SIGN_IN)));
                return;
            }
            
            //获取缓存中的信息(根据自己的业务进行拓展)
            HashMap<String,Object> hashMap = (HashMap<String, Object>) redisUtil.hget(auth_token);
            if (null == hashMap){
                //用户信息不存在或转换错误，返回错误信息
                response.getWriter().write(JSON.toJSONString(GenericResponse.response(ServiceError.GLOBAL_ERR_NO_SIGN_IN)));
                return;
            }
            //更新token过期时间
            redisUtil.setKeyExpire(auth_token,expirationMilliSeconds);
        	UserDetail userDetail = jwtUtils.getUserFromToken(auth_token);
            if (jwtUtils.validateToken(auth_token, userDetail)) {
            	userDetail.setAuthorities((Set<? extends GrantedAuthority>) hashMap.get("authorities"));
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetail, null, userDetail.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                logger.info(String.format("Authenticated userDetail %s, setting security context", username));
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }
        chain.doFilter(request, response);
    }
}
