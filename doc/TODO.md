In order:

* User manipulation
  * How are keys delivered?
* Group manipulation
* Secret manipulation
* API clean-up/once-over
* client clean-up
* First Relase!
* web interface
* 1.0

Caffiene-addled thought:

All the user/group modifications are handled by a separate admin API

requesting secrets is not done per-secret, but by requesitng all available secrets.

    GET /secrets

Changing secrets is done via HTTP POST to a URL like `/secrets/<id>`

	{
	  "rev": 1,
	  "secret": "<secret>"
	}
