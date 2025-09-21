# 🛡 Vulnerability Report

## Missing Content-Security-Policy
- **URL:** http://testphp.vulnweb.com
- **Severity:** Medium
- **Description:** Helps prevent XSS

## Missing Strict-Transport-Security
- **URL:** http://testphp.vulnweb.com
- **Severity:** Medium
- **Description:** Enforces HTTPS

## HTTPS not enforced
- **URL:** http://testphp.vulnweb.com
- **Severity:** High
- **Description:** Website should enforce HTTPS for security

## Possible SQL Injection
- **URL:** http://testphp.vulnweb.com/search.php?test=query
- **Payload:** `' OR '1'='1`
- **Severity:** High
- **Description:** Database error message detected

## Possible SQL Injection
- **URL:** http://testphp.vulnweb.com/search.php?test=query
- **Payload:** `' OR 1=1 --`
- **Severity:** High
- **Description:** Database error message detected

## Possible SQL Injection
- **URL:** http://testphp.vulnweb.com/search.php?test=query
- **Payload:** `" OR "1"="1`
- **Severity:** High
- **Description:** Database error message detected

## Possible SQL Injection
- **URL:** http://testphp.vulnweb.com/search.php?test=query
- **Payload:** `'; WAITFOR DELAY '0:0:5' --`
- **Severity:** High
- **Description:** Database error message detected

## Possible SQL Injection
- **URL:** http://testphp.vulnweb.com/search.php?test=query
- **Payload:** `' OR '1'='1`
- **Severity:** High
- **Description:** Database error message detected

## Possible SQL Injection
- **URL:** http://testphp.vulnweb.com/search.php?test=query
- **Payload:** `' OR 1=1 --`
- **Severity:** High
- **Description:** Database error message detected

## Possible SQL Injection
- **URL:** http://testphp.vulnweb.com/search.php?test=query
- **Payload:** `" OR "1"="1`
- **Severity:** High
- **Description:** Database error message detected

## Possible SQL Injection
- **URL:** http://testphp.vulnweb.com/search.php?test=query
- **Payload:** `'; WAITFOR DELAY '0:0:5' --`
- **Severity:** High
- **Description:** Database error message detected

## Possible SQL Injection
- **URL:** http://testphp.vulnweb.com/guestbook.php
- **Payload:** `' OR '1'='1`
- **Severity:** High
- **Description:** Database error message detected

## Possible SQL Injection
- **URL:** http://testphp.vulnweb.com/guestbook.php
- **Payload:** `' OR 1=1 --`
- **Severity:** High
- **Description:** Database error message detected

## Possible SQL Injection
- **URL:** http://testphp.vulnweb.com/guestbook.php
- **Payload:** `" OR "1"="1`
- **Severity:** High
- **Description:** Database error message detected

## Possible SQL Injection
- **URL:** http://testphp.vulnweb.com/guestbook.php
- **Payload:** `'; WAITFOR DELAY '0:0:5' --`
- **Severity:** High
- **Description:** Database error message detected

## Possible SQL Injection
- **URL:** http://testphp.vulnweb.com/guestbook.php
- **Payload:** `' OR '1'='1`
- **Severity:** High
- **Description:** Database error message detected

## Possible SQL Injection
- **URL:** http://testphp.vulnweb.com/guestbook.php
- **Payload:** `' OR 1=1 --`
- **Severity:** High
- **Description:** Database error message detected

## Possible SQL Injection
- **URL:** http://testphp.vulnweb.com/guestbook.php
- **Payload:** `" OR "1"="1`
- **Severity:** High
- **Description:** Database error message detected

## Possible SQL Injection
- **URL:** http://testphp.vulnweb.com/guestbook.php
- **Payload:** `'; WAITFOR DELAY '0:0:5' --`
- **Severity:** High
- **Description:** Database error message detected

## Possible SQL Injection
- **URL:** http://testphp.vulnweb.com/userinfo.php
- **Payload:** `' OR '1'='1`
- **Severity:** High
- **Description:** Database error message detected

## Possible SQL Injection
- **URL:** http://testphp.vulnweb.com/userinfo.php
- **Payload:** `' OR 1=1 --`
- **Severity:** High
- **Description:** Database error message detected

## Possible SQL Injection
- **URL:** http://testphp.vulnweb.com/userinfo.php
- **Payload:** `" OR "1"="1`
- **Severity:** High
- **Description:** Database error message detected

## Possible SQL Injection
- **URL:** http://testphp.vulnweb.com/userinfo.php
- **Payload:** `'; WAITFOR DELAY '0:0:5' --`
- **Severity:** High
- **Description:** Database error message detected

## Possible SQL Injection
- **URL:** http://testphp.vulnweb.com/userinfo.php
- **Payload:** `' OR '1'='1`
- **Severity:** High
- **Description:** Database error message detected

## Possible SQL Injection
- **URL:** http://testphp.vulnweb.com/userinfo.php
- **Payload:** `' OR 1=1 --`
- **Severity:** High
- **Description:** Database error message detected

## Possible SQL Injection
- **URL:** http://testphp.vulnweb.com/userinfo.php
- **Payload:** `" OR "1"="1`
- **Severity:** High
- **Description:** Database error message detected

## Possible SQL Injection
- **URL:** http://testphp.vulnweb.com/userinfo.php
- **Payload:** `'; WAITFOR DELAY '0:0:5' --`
- **Severity:** High
- **Description:** Database error message detected

## Reflected XSS
- **URL:** http://testphp.vulnweb.com/search.php?test=query
- **Payload:** `<script>alert(1)</script>`
- **Severity:** High
- **Description:** Payload reflected unescaped in response

## Reflected XSS
- **URL:** http://testphp.vulnweb.com/search.php?test=query
- **Payload:** `'"><img src=x onerror=alert(1)>`
- **Severity:** High
- **Description:** Payload reflected unescaped in response

## Reflected XSS
- **URL:** http://testphp.vulnweb.com/guestbook.php
- **Payload:** `<script>alert(1)</script>`
- **Severity:** High
- **Description:** Payload reflected unescaped in response

## Reflected XSS
- **URL:** http://testphp.vulnweb.com/guestbook.php
- **Payload:** `'"><img src=x onerror=alert(1)>`
- **Severity:** High
- **Description:** Payload reflected unescaped in response

## Open Redirect
- **URL:** http://testphp.vulnweb.com/Mod_Rewrite_Shop?next=https://evil.com
- **Payload:** `https://evil.com`
- **Severity:** Medium
- **Description:** Open redirect detected

## Open Redirect
- **URL:** http://testphp.vulnweb.com/Mod_Rewrite_Shop?next=//evil.com
- **Payload:** `//evil.com`
- **Severity:** Medium
- **Description:** Open redirect detected

## Open Redirect
- **URL:** http://testphp.vulnweb.com/hpp?next=https://evil.com
- **Payload:** `https://evil.com`
- **Severity:** Medium
- **Description:** Open redirect detected

## Open Redirect
- **URL:** http://testphp.vulnweb.com/hpp?next=//evil.com
- **Payload:** `//evil.com`
- **Severity:** Medium
- **Description:** Open redirect detected

