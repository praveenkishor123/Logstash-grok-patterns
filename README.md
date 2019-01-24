# Collection of logstash commonly used grok patterns

## Common usage

1. USERNAME [a-zA-Z0-9._-]+

2. USER %{USERNAME}

3. INT (?:[+-]?(?:[0-9]+))

4. BASE10NUM (?<![0-9.+-])(?>[+-]?(?:(?:[0-9]+(?:\.[0-9]+)?)|(?:\.[0-9]+)))

5. NUMBER (?:%{BASE10NUM})

6. BASE16NUM (?<![0-9A-Fa-f])(?:[+-]?(?:0x)?(?:[0-9A-Fa-f]+))

7. BASE16FLOAT \b(?<![0-9A-Fa-f.])(?:[+-]?(?:0x)?(?:(?:[0-9A-Fa-f]+(?:\.[0-9A-Fa-f]*)?)|(?:\.[0-9A-Fa-f]+)))\b

8. POSINT \b(?:[1-9][0-9]*)\b

9. NONNEGINT \b(?:[0-9]+)\b

10. WORD \b\w+\b

11. NOTSPACE \S+

12. SPACE \s*

13. DATA .*?

14. GREEDYDATA .*

15. QUOTEDSTRING (?>(?<!\\)(?>"(?>\\.|[^\\"]+)+"|""|(?>'(?>\\.|[^\\']+)+')|''|(?>`(?>\\.|[^\\`]+)+`)|``))

16. UUID [A-Fa-f0-9]{8}-(?:[A-Fa-f0-9]{4}-){3}[A-Fa-f0-9]{12}

## Networking

1. MAC (?:%{CISCOMAC}|%{WINDOWSMAC}|%{COMMONMAC})

2. CISCOMAC (?:(?:[A-Fa-f0-9]{4}\.){2}[A-Fa-f0-9]{4})

3. WINDOWSMAC (?:(?:[A-Fa-f0-9]{2}-){5}[A-Fa-f0-9]{2})

4. COMMONMAC (?:(?:[A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2})

5. IPV6 ((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?

6. IPV4 (?<![0-9])(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))(?![0-9])

7. IP (?:%{IPV6}|%{IPV4})

8. HOSTNAME \b(?:[0-9A-Za-z][0-9A-Za-z-]{0,62})(?:\.(?:[0-9A-Za-z][0-9A-Za-z-]{0,62}))*(\.?|\b)

9. HOST %{HOSTNAME}

10. IPORHOST (?:%{HOSTNAME}|%{IP})

11. HOSTPORT %{IPORHOST}:%{POSINT}


## paths

1. PATH (?:%{UNIXPATH}|%{WINPATH})

2. UNIXPATH (?>/(?>[\w_%!$@:.,-]+|\\.)*)+

3. TTY (?:/dev/(pts|tty([pq])?)(\w+)?/?(?:[0-9]+))

4. WINPATH (?>[A-Za-z]+:|\\)(?:\\[^\\?*]*)+

5. URIPROTO [A-Za-z]+(\+[A-Za-z+]+)?

6. URIHOST %{IPORHOST}(?::%{POSINT:port})?

#### uripath comes loosely from RFC1738, but mostly from what Firefox doesn't turn into %XX
7. URIPATH (?:/[A-Za-z0-9$.+!*'(){},~:;=@#%_\-]*)+

8. URIPARAM \?(?:[A-Za-z0-9]+(?:=(?:[^&]*))?(?:&(?:[A-Za-z0-9]+(?:=(?:[^&]*))?)?)*)?

9. URIPARAM \?[A-Za-z0-9$.+!*'|(){},~@#%&/=:;_?\-\[\]]*

10. URIPATHPARAM %{URIPATH}(?:%{URIPARAM})?

11. URI %{URIPROTO}://(?:%{USER}(?::[^@]*)?@)?(?:%{URIHOST})?(?:%{URIPATHPARAM})?


## Months: January, Feb, 3, 03, 12, December

1. MONTH \b(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\b

2. MONTHNUM (?:0?[1-9]|1[0-2])

3. MONTHNUM2 (?:0[1-9]|1[0-2])

4. MONTHDAY (?:(?:0[1-9])|(?:[12][0-9])|(?:3[01])|[1-9])


## Days

1. DAY (?:Mon(?:day)?|Tue(?:sday)?|Wed(?:nesday)?|Thu(?:rsday)?|Fri(?:day)?|Sat(?:urday)?|Sun(?:day)?)


## Years

1. YEAR (?>\d\d){1,2}

2. HOUR (?:2[0123]|[01]?[0-9])

3. MINUTE (?:[0-5][0-9])


## '60' is a leap second in most time standards and thus is valid.
## Time

1. SECOND (?:(?:[0-5]?[0-9]|60)(?:[:.,][0-9]+)?)

2. TIME (?!<[0-9])%{HOUR}:%{MINUTE}(?::%{SECOND})(?![0-9])


## datestamp is YYYY/MM/DD-HH:MM:SS.UUUU (or something like it)

1. DATE_US %{MONTHNUM}[/-]%{MONTHDAY}[/-]%{YEAR}

2. DATE_EU %{MONTHDAY}[./-]%{MONTHNUM}[./-]%{YEAR}

3. ISO8601_TIMEZONE (?:Z|[+-]%{HOUR}(?::?%{MINUTE}))

4. ISO8601_SECOND (?:%{SECOND}|60)

5. TIMESTAMP_ISO8601 %{YEAR}-%{MONTHNUM}-%{MONTHDAY}[T ]%{HOUR}:?%{MINUTE}(?::?%{SECOND})?%{ISO8601_TIMEZONE}?

6. DATE %{DATE_US}|%{DATE_EU}

7. DATESTAMP %{DATE}[- ]%{TIME}

8. TZ (?:[PMCE][SD]T|UTC)

9. DATESTAMP_RFC822 %{DAY} %{MONTH} %{MONTHDAY} %{YEAR} %{TIME} %{TZ}

10. DATESTAMP_RFC2822 %{DAY}, %{MONTHDAY} %{MONTH} %{YEAR} %{TIME} %{ISO8601_TIMEZONE}

11. DATESTAMP_OTHER %{DAY} %{MONTH} %{MONTHDAY} %{TIME} %{TZ} %{YEAR}

12. DATESTAMP_EVENTLOG %{YEAR}%{MONTHNUM2}%{MONTHDAY}%{HOUR}%{MINUTE}%{SECOND}


## Syslog Dates: Month Day HH:MM:SS

1. SYSLOGTIMESTAMP %{MONTH} +%{MONTHDAY} %{TIME}

2. PROG (?:[\w._/%-]+)

3. SYSLOGPROG %{PROG:program}(?:\[%{POSINT:pid}\])?

4. SYSLOGHOST %{IPORHOST}

5. SYSLOGFACILITY <%{NONNEGINT:facility}.%{NONNEGINT:priority}>

6. HTTPDATE %{MONTHDAY}/%{MONTH}/%{YEAR}:%{TIME} %{INT}


## Shortcuts

1. QS %{QUOTEDSTRING}


## Log formats

1. SYSLOGBASE %{SYSLOGTIMESTAMP:timestamp} (?:%{SYSLOGFACILITY} )?%{SYSLOGHOST:logsource} %{SYSLOGPROG}:

2. COMMONAPACHELOG %{IPORHOST:clientip} %{USER:ident} %{USER:auth} \[%{HTTPDATE:timestamp}\] "(?:%{WORD:verb} %{NOTSPACE:request}(?: HTTP/%{NUMBER:httpversion})?|%{DATA:rawrequest})" %{NUMBER:response} (?:%{NUMBER:bytes}|-)

3. COMBINEDAPACHELOG %{COMMONAPACHELOG} %{QS:referrer} %{QS:agent}


## Log Levels

LOGLEVEL ([A|a]lert|ALERT|[T|t]race|TRACE|[D|d]ebug|DEBUG|[N|n]otice|NOTICE|[I|i]nfo|INFO|[W|w]arn?(?:ing)?|WARN?(?:ING)?|[E|e]rr?(?:or)?|ERR?(?:OR)?|[C|c]rit?(?:ical)?|CRIT?(?:ICAL)?|[F|f]atal|FATAL|[S|s]evere|SEVERE|EMERG(?:ENCY)?|[Ee]merg(?:ency)?)

