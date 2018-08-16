FROM oapass/fcrepo:4.7.5-2.3-SNAPSHOT

RUN rm -rf /usr/local/tomcat/webapps/pass-user-service
COPY tomcat-users.xml /usr/local/tomcat/conf/tomcat-users.xml
COPY pass-user-service.war /usr/local/tomcat/webapps/
COPY pass-authz-filters-shaded.jar /usr/local/tomcat/lib
COPY fcrepo.xml /usr/local/tomcat/conf/Catalina/localhost/