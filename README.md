Enunciate backend
=================

This module uses [enunciate](http://enunciate.codehaus.org/) to create and publish 2 webservice endpoints for the Grisu API as well as the API documentation (example [here](https://compute-dev.services.bestgrid.org/) ) from the Javadoc comments.

Prerequisites
--------------------

In order to build the backend from the git sources, you need: 

- Sun Java Development Kit (version ≥ 6)
- [git](http://git-scm.com) 
- [Apache Maven](http://maven.apache.org) (version >=2)


Checking out sourcecode
-------------------------------------

 `git clone git://github.com/grisu/enunciate-backend.git`

Building Grisu using Maven
------------------------------------------

To build one of the above modules, cd into the module root directory of the module to build and execute: 

    cd enunciate-backend
    mvn clean install

This will build a war file that can be deployed into a container and also a deb file that can be installed on a Debian based machine.

Configuring the backend
--------------------------------------

Please refer to the documentation [here](https://github.com/grisu/grisu/wiki/How-to-configure-a-Grisu-backend)

