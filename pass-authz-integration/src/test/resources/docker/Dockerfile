FROM oapass/fcrepo:4.7.5-2.0-SNAPSHOT-5

COPY pass-user-service.war /usr/local/tomcat/webapps/
COPY pass-authz-filters-shaded.jar /usr/local/tomcat/lib
COPY web.xml /usr/local/tomcat/conf

RUN sed -e 's:some-header:pass-roles:' -i ${CATALINA_HOME}/webapps/fcrepo/WEB-INF/classes/spring/auth-repo.xml

