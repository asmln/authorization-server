package ru.cmlt.oauth2.authorizationserver.controllers;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Created by Anatoly Samoylenko on 30.04.2018.
 */

@RestController
public class UserController {

    @RequestMapping({ "/user", "/me" })
    public Map<String, String> user(Principal principal) {
        var map = new LinkedHashMap<String, String>();
        map.put("name", principal.getName());
        return map;
    }

}
