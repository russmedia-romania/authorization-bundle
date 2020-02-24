# Authorization Bundle

## Installation
```
composer require rmc/authorization-bundle
```
## Requirements
 - php
 - Symfony bundle
 - Symfony Finder
 - Symfony Console
 - Api Platform
 - Doctrine Bundle
 - Phpredis
 
 ## Usage
To implement authorization for entities it is required to implement the `SecuredInterface` for the Entities that need Authorization.

![Image description](https://i.imgur.com/WPlRoCo.png)

If the entity implements the SecuredInterface it is only needed to add the is_granted attribute to `@ApiResource` annotation. Not all operations are needed for the authorization to work.

![Image description](https://i.imgur.com/6Q08tmf.png)

As you can see from the previous screenshot the collection operation `POST` instead of `security` uses `security_post_denormalize`, that is because in case of a POST request the data firstly needs to be persisted in doctrine and only afterwards we can check for authorization.
That is a very important thing to keep in mind, if that operation will use just `security` no one will be able to `POST` any resources.

## Accepted Attributes
The only accepted attributes are `READ` , `WRITE`, `DELETE` , any other attribute used will trigger an `AccessDeniedException`!

## Things to keep in mind
- The script will be set to only run when a deployment will run
- The users access rights will come from redis
