examples/webserver_test
^^^^^^^^^^^^^^^^^^

  This is an example of webserver_test.
  It is executed by "webserver_test <method> <uri> [options]" command.
  <method> and <url> parameters should be given, [options] parameters are optional.
  <method> is one if "GET", "POST", "PUT", "DELETE".
  <url> should start with "http://" or "https://".

  [options] parameter support several different options.
   chunked=1        : Enable chunked encoding (default is disabled)
   entity=DATA      : Input entity data (default is NULL)
   test_entity=SIZE : Input test entity dummy data (default is 0)

  The way of sending an entity is content-length by default.

  Configs (see the details on Kconfig):
  * CONFIG_EXAMPLES_WEBSERVER_TEST
