# Pass Authorization Tools

[![Build Status](https://travis-ci.org/OA-PASS/pass-authz.svg?branch=master)](https://travis-ci.org/OA-PASS/pass-authz)

* `pass-authz-roles` Determines the access roles of a given user, used for enforcement via access control lists.
* `pass-authz-listener` A service which listens for changes to resources (e.g. submission of a resource), and then enacts changes to their access control list (making it read-only, for example).
* `pass-authz-tools` Tools for manually manipulating or setting permissions in the repository
* `pass-user-service` - An http servlet that provides details of the currently logged in user (e.g. links to their `User` resource in the repository).  Creates a new `User` resources for those who don't have one pre-existing already.

## Quick reference

All `pass-authz` components communicate with the repository, and require standard pass client environment variables to be set where they diverge from the defaults:

* `PASS_FEDORA_BASEURL` (URI, Default `http://localhost:8080/fcrepo/rest`). Fedora's repository root URL
* `PASS_FEDORA_USER` (String, default `fedoraAdmin`). The user for requests to Fedora.  In most cases, it should be a privileged backend user (such as `FedoraAdmin`, or something with a `pass-backend` role)
* `PASS_FEDORA_PASWORD` (String, default `moo`).  The Fedora password to use when making requests to Fedora
* `PASS_ELASTICSEARCH_URL` (URI, default `http://localhost:9200/pass`).  The elasticsearch base URI

### pass-authz-roles

This is a servlet filter to be deployed with Fedora (it is part of the `pass-docker` fcrepo image).  Its primary purpose is to inspect shibboleth headers for requests from logged-in users, and provide Fedora with a list of [authorization roles](#Authorization-roles) to use when enforcing [ACLs](#ACLs).  Roles are provided by attaching an http header to the request to Fedora, containing a list of role URIs.  The authz filter makes requests to Fedora in order to inspect a user's `User` resource for roles, and uses the PASS client in order to do that.

Configuration environment variables:

* Standard pass client environment variables (`PASS_FEDORA_*`, `PASS_ELASTICSEARCH_*`).
* `AUTHZ_ALLOW_EXTERNAL_ROLES` (Boolean, default `false`).  Normally, the `pass-authz-roles` is the sole provider of roles.  Any pre-existing values in the role header will be erased.  Set to true to pass through any roles already defined in the http request (insecure, but helpful for debugging)
* `AUTHZ_HEADER_NAME` (String, default `pass-roles`).  HTTP header name to populate with a list of roles.  This is the manner by which roles are provided to Fedora
* `AUTHZ_HEADER_SEPARATOR` (String, default `,`).  Separator string/character for the list of URIs in the roles http header.
* `AUTHZ_SHIB_USE_HEADERS` (String, default `false`).  If true, will look for shibboleth attributes in http headers.  By default, it expects shib headers to be provided as request attributes (i.e. environment variables, via the AJP protocol`).

### pass-authz-listener

This is a service that listens to Fedora messages for updated or new resources, and creates/modifies their ACLS based on some policy.  It is a java application intended to be run in a Docker container.

At the moment, it:

* Assures Submission resources read-only if their status is `submitted`
* Assures that Submissions, when newly created, are writable only by their creator.

Configuration environment variables:

* `PASS_AUTHZ_QUEUE` (String, no default).  Name of the JMS queue to listen for Fedora messages.  For example. `Consumer.authz.VirtualTopic.pass.docker`
* `PASS_BACKEND_ROLE` (URI, no default).  PASS backend role URI.  If unset, will not be used.  See [authorization roles](#authorization-roles).
* `PASS_GRANTADMIN_ROLE` (URI, no default).  Grant admin role URI.  If unset, will not be used.  See [authorization roles](#authorization-roles).
* `PASS_SUBMITTER_ROLE` (URI, no default).  Submitter role URI.  If unset, will not be used.  See [authorization roles](#authorization-roles).
* `JMS_BROKERURL` (URI, default `tcp://localhost:61616`) JMS broker connection URL.
* `JMS_USERNAME` (String, no default).  JMS connection username.  Leave undefined if it is not password protected.
* `JMS_PASSWORD` (String, no default).  JMS connection password.  Leave undefined if it is not password protected.

### pass-authz-tools

Contains command-line applications that manually iterate the resources in the repository, and adjust (or add) ACLs that comply with the PASS [authorization policy](#ACLs).  These applications take no command-line arguments; they just do what they need to do in order to iterate resources and set ACLs.  

The applications are:

* `individual-permissions` - scans individual resources in the repository and sets their fine-grained permissions.
* `container-permissions` - sets the coarse container-level (e.g. `submissions/`, `grants/`) permissions for the repository.

Configuration:

The only configuration these tools need are standard PASS java client [properties](https://github.com/OA-PASS/java-fedora-client#configuration) for Fedora username,  password, and baseURI.

For example:

    java -Dpass.fedora.baseurl=http://example.org/fcrepo/rest -Dpass.fedora.user=fedoraAdmin -Dpass.fedora.password=pass -jar pass-authz-tools-${version}-SNAPSHOT-individual-permissions-exe.jar
    
### pass-authz-usertoken

Contains a library for reading and writing user tokens - a secure mechanism for conveying the identity of an invited new User for the purpose of granting them permissions on resources when they log into the repository for the first time.

A user token encodes a reference (a placeholder URI identifying the invited user), and a resource that contains that reference.  The reference is typically a `mailto:` uri containing a name and e-mail address, but that is neither required nor relevant to this libary.

User tokens are used as follows, according to the proxy user use case:

* A user requests participation (e.g. approval) for a submission for somebody not yet present in pass, this results in a `mailto:` URI being placed in the `Submission`, with the intended person's e-mail address.
* Notification services generates an e-mail, which contains a link containing a user token.  This token is used for assigning "whoever used this token to log in" a User resource in pass.
* The placeholder URIs in the given resource are replaced with the User's new User URI
* The User is granted appropriate permissions to modify the submission.

The tokens are intended for single-use only, on a specific resource only, for a specific recipient (and therefore placeholder) only.  While PASS cannot protect against the resipient of this token maliciously providing it to another individual, it can limit usage of this token to its one-time intended purpose, and assure that tokens have been issued by notification services.  For this reason, the resource and reference URIs associated with a token are encrypted.  A shared encryption key is required to create, read, or validate tokens.

A key may be generated by executing the key generation tool with no arguments

    java -jar pass-authz-usertoken-${version}-keygen-exe.jar
    
To create a token, use the `TokenFactory`.  PASS resource URIs and reference URIs are required:

    Key key = Key.fromString(generatedKey);
    TokenFactory tokenFactory = new TokenFactory(key);
    
    Token token = tokenFactory
                            .forPassResource(submissionUri)
                            .withReference(mailtoUri);
                            
It is then possible to append the encrypted/encoded token to a URL as a parameter:

    URI uriWithToken = token.addTo(uriWithoutToken);
    
Likewise, it's possible to decode URIs containing encoded tokens

    Token received = tokenFactory.fromUri(uriWithToken);
    URI resource = received.getPassResource();
    URI reference = received.getReference();


## pass-user-service

The User service is an http servlet, intended to be deployed in the same servlet container in Fedora, which serves two functions:

1. Find the `User` resource that corresponds to the authenticated user making the request.  This is essential for Ember to discover the indentity of the logged-in user.  It achieves this by examining the headers that are present as attributes released by Shibboleth, then querying the repository based on that.
2. Create new `User`s if there is  `User` corresponding to the authenticated requester.

Configuration environment variables:

* Standard pass client environment variables (`PASS_FEDORA_*`, `PASS_ELASTICSEARCH_*`).
* `AUTHZ_SHIB_USE_HEADERS` (String, default `false`).  If true, will look for shibboleth attributes in http headers.  By default, it expects shib headers to be provided as request attributes (i.e. environment variables, via the AJP protocol`).

### Developer notes

To dun the user service localy for development, do the following:

1. Go to `pass-authz-integration`
2. run `mvn cargo:run -Pstandard`.  This will start Fedora and the user service in the same Tomcat on port 8080
3. Go to [http://localhost:8080/pass-user-service/whoami](http://localhost:8080/pass-user-service/whoami).  There you should see the user service output

## Appendix

### Authorization roles

[High-level roles](https://oa-pass.github.io/pass-data-model/documentation/User.html#role-options) in PASS for users are submitters or grant admins.  For protecting repository resources and writing ACLS that grant or deny access based on role, these roles are further qualified by domain, e.g. "Johns hopkins submitter", or "Harvard grant admin", and are represented by URIs.

All roles are designated with a baseURI

    http://oapass.org/ns/roles/

... followed by the authorization domain (identical to Shibboleth auth domain)

    http://oapass.org/ns/roles/johnshopkins.edu

... then have a specific role name as a fragment

    http://oapass.org/ns/roles/johnshopkins.edu#submitter

There is also a `pass-backend` role for non-human services on the back end.  Therefore, a complete set of roles, for the sake of granting or denying permissions, may be:

* `http://oapass.org/ns/roles/johnshopkins.edu#submitter` (johnshopkins.edu submitter)
* `http://oapass.org/ns/roles/johnshopkins.edu#admin` (johnshopkins.edu grant admin)
* `http://oapass.org/ns/roles/johnshopkins.edu#pass-backend` (johnsjopkins.edu backend)

### ACLs

ACLs are RDF documents that grant read, write, or append access to repository resources, see [SOLID WebAC](https://github.com/solid/web-access-control-spec).   In the context of PASS, ACLS grant these permissions to individual users (by their `User` resource URI in pass), or to a roll (by that role's URI).

At a high level, the way they work is:

* If a resource has an ACL linked to it, the permissions specified in that ACL are used for authorization purposes.  This can also be called "individual" or "fine-grained" permissions.
* If a resource does not have an ACL, then it inherits the permissions of its parent container.  This can also be called "coarse-grained" permisions.  This is used for, say, granting world-readability to Journal resources, or making granting permission to create new Submissions in the `Submissions` container.

The complete list of container-level permissions reflected in the coarse-grained ACLs is accessible as [pass-authz-acl/src/main/resources/containers.yml](pass-authz-acl/src/main/resources/containers.yml)
