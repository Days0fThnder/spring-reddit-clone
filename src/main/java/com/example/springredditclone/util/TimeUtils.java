package com.example.springredditclone.util;

import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;

public class TimeUtils {

    public static ZoneOffset timeZoneOffset(){
        OffsetDateTime odt = OffsetDateTime.now ( ZoneId.systemDefault () );
        ZoneOffset zoneOffset = odt.getOffset();
        return zoneOffset;
    }
}
