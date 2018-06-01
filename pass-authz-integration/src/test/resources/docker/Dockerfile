FROM oapass/fcrepo:4.7.5-2.2-SNAPSHOT

COPY pass-user-service.war /usr/local/tomcat/webapps/
COPY pass-authz-filters-shaded.jar /usr/local/tomcat/lib
COPY conf/* /usr/local/tomcat/conf/
COPY WEB-INF/* /usr/local/tomcat/webapps/fcrepo/WEB-INF/
