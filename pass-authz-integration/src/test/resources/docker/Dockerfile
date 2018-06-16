FROM oapass/fcrepo:4.7.5-2.2-SNAPSHOT-7

RUN rm -rf /usr/local/tomcat/webapps/pass-user-service
COPY pass-user-service.war /usr/local/tomcat/webapps/
COPY pass-authz-filters-shaded.jar /usr/local/tomcat/lib