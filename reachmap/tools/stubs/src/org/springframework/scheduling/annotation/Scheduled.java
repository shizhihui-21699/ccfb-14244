package org.springframework.scheduling.annotation;
import java.lang.annotation.*;
@Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD)
public @interface Scheduled { long fixedRate() default -1; long fixedDelay() default -1; String cron() default ""; }
