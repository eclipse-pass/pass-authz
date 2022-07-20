FROM oapass/fcrepo:0.1.0@sha256:749cdb6d44ed723f7bd0886a75190f79353078cf4738aa290e5ec1176a9340e4

RUN rm -rf /usr/local/tomcat/webapps/pass-user-service && \
    rm /usr/local/tomcat/lib/pass-authz* && \
    sed -e "s:org.dataconservancy.pass.authz.filter:org.dataconservancy.pass.authz.roles:"     \
        -i /usr/local/tomcat/conf/web.xml 
    
COPY tomcat-users.xml /usr/local/tomcat/conf/tomcat-users.xml
COPY pass-user-service.war /usr/local/tomcat/webapps/
COPY pass-authz-roles.jar /usr/local/tomcat/lib
COPY pass-authz-core-shaded.jar /usr/local/tomcat/lib
COPY fcrepo.xml /usr/local/tomcat/conf/Catalina/localhost/
