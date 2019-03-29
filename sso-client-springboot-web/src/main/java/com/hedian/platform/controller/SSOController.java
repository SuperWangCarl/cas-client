package com.hedian.platform.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;


@Controller
public class SSOController {
    @RequestMapping("/hello")
    @ResponseBody
    public String helloPage(){
        return "Hello SSO";
    }
}
