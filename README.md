# PHP CryptoLinks for stateless authorization

This directory holds a small PHP library which allows to securely pass information
in HTTP query parameters.

## The problem which is solved

Imagine you want to allow a visitor of your website to access a specific file on
your webserver. You don't want to rename or expose it in a special directory. You
also don't want to manage a database or some other stateful information where
you could store tokens (identifiers, ...) which map to the actual file names.

## Deliver encrypted information to the visitor

The approach of *CryptoLinks* is to encryp the sensitive information and pass them
to the user. Instead of an insignificant token or id, she gets an insignificant
hash-like string which she will pass in a subsequent request.

Since we encrypt the information, we can also profit from the *signing* property
of encryption: That is, if you only want to make sure that the user does not access
anything but the link you want her to access, you can use the library to *sign your
links*.

## Usage, intention, credits

There is a standalone PHP example which demonstrates the functionality.

I wrote this library as a simple frontend for the amazing
[php-encryption](https://github.com/defuse/php-encryption) library.

My personal intention was to use this library for my *PublicCode* project.

License: Use this code as public domain.