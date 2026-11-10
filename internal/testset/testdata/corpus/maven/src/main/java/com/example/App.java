package com.example;

import org.apache.commons.lang3.StringUtils;

// Minimal real Maven build for the pull-through proxy test set.
public final class App {
    public static void main(String[] args) {
        System.out.println(StringUtils.isBlank("") ? "commons-lang3 ok" : "fail");
    }
}
