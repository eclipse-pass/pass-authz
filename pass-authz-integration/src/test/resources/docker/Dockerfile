FROM oapass/fcrepo:0.1.0@sha256:ffa09bb4f3481ef2840f5e40d8a214609da0600ad00f9a741f69b18a4fa4c3a1

RUN rm -rf /usr/local/tomcat/webapps/pass-user-service && \
    rm /usr/local/tomcat/lib/pass-authz* && \
    sed -e "s:org.dataconservancy.pass.authz.filter:org.dataconservancy.pass.authz.roles:"     \
        -i /usr/local/tomcat/conf/web.xml 
    
COPY tomcat-users.xml /usr/local/tomcat/conf/tomcat-users.xml
COPY pass-user-service.war /usr/local/tomcat/webapps/
COPY pass-authz-roles.jar /usr/local/tomcat/lib
COPY pass-authz-core-shaded.jar /usr/local/tomcat/lib
COPY fcrepo.xml /usr/local/tomcat/conf/Catalina/localhost/
