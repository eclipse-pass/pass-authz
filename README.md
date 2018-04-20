# Pass Authoriation Tools

## User service

1. Go to `pass-authz-integration`
2. run `mvn cargo:run -Pstandard`.  This will start Fedora and the user service in the same Tomcat on port 8080
3. Go to [http://localhost:8080/pass-user-service/whoami](http://localhost:8080/pass-user-service/whoami).  There you should see the stub/skeleton user service output