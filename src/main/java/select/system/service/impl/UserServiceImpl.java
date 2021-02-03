package select.system.service.impl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import redis.clients.jedis.Jedis;
import select.base.Constants;
import select.base.Result;
import select.constants.BaseEnums;
import select.system.dao.RoleMapper;
import select.system.dao.UserMapper;
import select.system.dao.UserRoleMapper;
import select.system.dto.Role;
import select.system.dto.User;
import select.system.dto.UserRole;
import select.system.service.UserService;
import select.util.JedisUtil;
import select.util.PageBean;
import select.util.Results;
import select.util.TokenUtil;

import javax.jws.soap.SOAPBinding;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * @author yeyuting
 * @create 2021/1/25
 */
@Service
public class UserServiceImpl implements UserService , UserDetailsService {

    @Autowired
    UserMapper userMapper ;

    @Autowired
    TokenUtil tokenUtil ;

    @Autowired
    JedisUtil jedisUtil ;

    @Autowired
    RoleMapper roleMapper ;

    @Autowired
    UserRoleMapper userRoleMapper ;

    public User selectByName(String username) {
      return  userMapper.selectByName(username) ;
    }

    public User selectById(int id){
        return userMapper.selectById(id) ;
    }

    public List<User> selectAll(){
        return userMapper.selectAll() ;
    }

    public boolean insertOne(User user) {
        return userMapper.insertOne(user) ;
    }

    public boolean insertMany(List<User> userList) {
        return userMapper.insertMany(userList) ;
    }
    public boolean updateOne(User user){
        return userMapper.updateOne(user) ;
    }

    public boolean deleteById(int id){
        return userMapper.deleteById(id) ;
    }

    public List<User> SelectByStartIndexAndPageSize(int startIndex , int pageSize) {
        return userMapper.SelectByStartIndexAndPageSize(startIndex,pageSize) ;
    }

    public List<User> selectByMap(Map<String ,Object> map){
        return userMapper.selectByMap(map) ;
    }

    public List<User> SelectByPageBean(PageBean pageBean) {
        return userMapper.SelectByPageBean(pageBean) ;
    }

    public List<User> selectByLike(Map<String , Object> map){
        return userMapper.selectByLike(map) ;
    }

    public Result loginCheck(User user , HttpServletResponse response){
        User user1 = userMapper.selectByName(user.getUserName()) ;
        if(user1 == null ){
            return Results.failure("用户不存在") ;
        }else if(!user1.getPassword().equals(user.getPassword())){
            return Results.failure("密码输入错误！") ;
        }
        Jedis jedis = jedisUtil.getSource() ;
        String jedisKey = jedis.get(user1.getUserName()) ;
        if(jedisKey != null){
            jedisUtil.delString(user1.getUserName());
        }
        String token = tokenUtil.generateToken(user1) ;
        System.out.println("token:" + token);
        user1.setToken(token);
        return Results.successWithData(user1);
    }


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        List<GrantedAuthority> grantedAuthorities = new ArrayList<>() ;
        User user = userMapper.selectByName(username) ;
        if(user == null){
            throw new UsernameNotFoundException("用户不存在！")  ;
        }
        List<UserRole> userRoles = userRoleMapper.selectList(user.getId()) ;
        for(UserRole userRole : userRoles){
            Role role = roleMapper.selectOne(userRole.getRoleId()) ;
            GrantedAuthority grantedAuthority = new SimpleGrantedAuthority(role.getRole()) ;
            grantedAuthorities.add(grantedAuthority) ;
        }
        //生成token
        //将原有的token值全部干掉，防止重复登陆
        Jedis jedis = jedisUtil.getSource();
        //存入键值对
        String jedisKey = jedis.get(user.getUserName()) ;
        if(jedisKey != null){
            jedisUtil.delString(user.getUserName());
        }

        String token = tokenUtil.generateToken(user) ;
        user.setToken(token);
        user.setGrantedAuthority("authority");
        user.setGrantedAuthorities(grantedAuthorities);
        jedisUtil.tokenToJedis(user);
        jedis.close();
        return new org.springframework.security.
                core.userdetails.User("user" , new BCryptPasswordEncoder().encode(user.getPassword()) , grantedAuthorities) ;

    }
}
