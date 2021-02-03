package select.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.util.AntPathMatcher;
import select.system.dao.PrivilegeMapper;
import select.system.dto.Privilege;
import select.system.dto.Role;

import java.util.Collection;
import java.util.List;

/**
 * @author yeyuting
 * @create 2021/1/28
 */
//用来匹配当前用户访问资源的URL和数据库中该资源对应的URL，
//和获取数据库中该资源对应的角色
public class FilterInvocationSecurityMetadataSource implements org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource {
    /**
     * 用于实现ant风格的Url匹配
     */
    AntPathMatcher antPathMatcher = new AntPathMatcher() ;

    @Autowired
    PrivilegeMapper privilegeMapper ;

    @Override
    public Collection<ConfigAttribute> getAttributes(Object o) throws IllegalArgumentException {
        /**
         * 从参数中获取当前请求的URL
         */
        String requestUrl = ((FilterInvocation) o).getRequestUrl() ;
        int len = requestUrl.indexOf("?");
        if(len != -1){
            requestUrl = requestUrl.substring(0,len);
        }
        List<Privilege> privilegeList = privilegeMapper.getAllPrivileges() ;
        for(Privilege privilege : privilegeList) {
            //将数据库中访问资源的URL与当前访问的URL进行ant风格匹配
            privilege.getPrivilegeUrl() ;
            if (antPathMatcher.match(privilege.getPrivilegeUrl() , requestUrl)) {
                //获取访问一个资源需要的角色
                List<Role> roleList = privilege.getRoleList() ;
                String[] roleArr = new String[roleList.size()] ;
                for(int i = 0 ; i < roleArr.length ; i++){
                    roleArr[i] = roleList.get(i).getRole() ;
                }
                return SecurityConfig.createList(roleArr) ;
            }
        }
        throw new AccessDeniedException("权限不足");
        //return null ;
    }

    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {

        return null;
    }

    @Override
    public boolean supports(Class<?> clazz) {

        return FilterInvocation.class.isAssignableFrom(clazz);
    }
}
