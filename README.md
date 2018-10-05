# confcrypt
As soon as an application is deployed or built on more than a single machine, you tend to start worrying about managing the configuration. There are a number of ways to approach this problem, but ultimately there's a need to protect sentisive inforamtion like database password and api tokens. While you can always store those directly in a config management system like AWS' Parameter Store, doing so means you can't track configuration changes in source control. This application provides yet another simple and straightforward means of hiding config information within source control.

[![CircleCI](https://circleci.com/gh/collegevine/confcrypt/tree/master.svg?style=svg)](https://circleci.com/gh/collegevine/confcrypt/tree/master)

## Installing confcrypt
#### Mac OSX


## Using confcrypt
- create a config
    `confcrypt create <filename>` creates a new empty confcrypt config named `<filename>.econf`. Internally, it looks like this:
    ```
    # confcrypt schema
    # Configuration parameters may be either a String, Int, or Boolean
    # Parameter schema take the following shape:
    # schema := [term | value | comment]
    #   term := confname : type
    #   confname := [a-z,A-Z,_,0-9]
    #   type := String | Int | Boolean
    #   value := confname = String
    #   comment := # String
    #
    # For example:
    # DB_CONN_STR : String
    # DB_CONN_STR = Connection String
    # USE_SSL : Boolean
    # USE_SSL = True
    # TIMEOUT_MS : Int
    # TIMEOUT_MS = 300
    ```
- read a config
    `confcrypt read --key <filename> <filename>`
    This command reads in the provided file, decrypts the configuration variables using the provided key, then prints them to stdout. This allows you to pipe the results to other utilities. Returns 0 on success.
- add a parameter
    `confcrypt add --key <filename> --name <String> --type <SchemaType> --vaue <String> <filename>
    Adds a new confguration parameter to the file. `--name` and `--value` are required, while `--type` is optional. If `--type` is provided, the schema record will be added immediately before the config variable. In total this adds two lines to the file. Returns 0 on sccess.
- remove a parameter
    `confcrypt delete --name <filename>
    Removes an existing config parameter & associated schema. Returns 0 on success or 1 if the parameter is not found in the file.
- edit a parameter in-place
    `confcrypt edit --key <filename> --name <String> --value <String> --type <SchemaType> <filename>`
    Modifies an existing configuration parameter in place, leaving all other lines unchanged. While this isn't how it's actually implemented, this operation is equivalent to piping `confcrypt read` to a new file, editing the parameter, then reencrypting it.
- validate a config
    `confcrypt validate --key <filename> <filename>`
    Checks that each config parameter matches the type of its schema. All errors are accumulated and returned at the end, with a response code equal to the number of failures.

- Using Amazon KMS instead of a local key
    The `--use-aws` flag changes the behavior of the `--key` parameter to represent a KMS key id rather than an on-disk rsa key file.

## The confcrypt file format
    ```
    # confcrypt schema
    # Configuration parameters may be either a String, Int, or Boolean
    # Parameter schema take the following shape:
    # schema := [term | value | comment]
    #   term := confname : type
    #   confname := [a-z,A-Z,_,0-9]
    #   type := String | Int | Boolean
    #   value := confname = String
    #   comment := # String
    #
    # For example:
    # DB_CONN_STR : String
    # DB_CONN_STR = Connection String
    # USE_SSL : Boolean
    # USE_SSL = True
    # TIMEOUT_MS : Int
    # TIMEOUT_MS = 300
    ```

    While the default config created via `confcrypt new ...` places the schema on line `n` and parameters on `n+1`, there's no required ordering for the file. In fact, you can choose to entirely omit the schema and only store configuration paraemters in an `econf` file, but this will cause `confcrypt validate` to fail.
