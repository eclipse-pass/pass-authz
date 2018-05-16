FROM oapass/fcrepo:4.7.5-2.0-SNAPSHOT-5

COPY pass-user-service.war /usr/local/tomcat/webapps/

RUN sed -e 's:some-header:pass-role:' -i ${CATALINA_HOME}/webapps/fcrepo/WEB-INF/classes/spring/auth-repo.xml

