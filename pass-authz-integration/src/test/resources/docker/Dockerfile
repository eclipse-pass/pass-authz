FROM oapass/fcrepo:4.7.5-2.0-SNAPSHOT-6

COPY pass-user-service.war /usr/local/tomcat/webapps/
COPY pass-authz-filters-shaded.jar /usr/local/tomcat/lib
COPY conf/* /usr/local/tomcat/conf/
COPY lib/* /usr/local/tomcat/lib/
COPY WEB-INF/ /usr/local/tomcat/webapps/fcrepo/WEB-INF/

RUN sed -e 's:some-header:pass-roles:' -i ${CATALINA_HOME}/webapps/fcrepo/WEB-INF/classes/spring/auth-repo.xml

