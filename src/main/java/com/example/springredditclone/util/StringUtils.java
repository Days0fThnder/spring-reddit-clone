package com.example.springredditclone.util;

public class StringUtils {

    public static String AppendRedditPrefix(String subredditName) {
        return "/r/"+subredditName;
    }
}
